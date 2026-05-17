/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux Hide - 原始策略 oracle 模式
 *
 * 策略：
 *   1. 通过 security_read_policy() 备份原始 Android sepolicy 二进制。
 *   2. 尝试 security_load_policy() 将备份解析为独立 policy 对象。
 *   3. context/access/setprocattr 查询优先走原始 policy 对象验证。
 *   4. policy 对象不可用时退回二进制 type 搜索（fallback）。
 *
 * 对抗 Duck-Detector-Refactoring:
 *   - u:r:app_zygote:s0         原始 policy 有 → 放行 → oracle: valid
 *   - u:r:ksu:s0                原始 policy 无 → -EINVAL → oracle: invalid ✓
 *   - u:object_r:system_data_file:s0  原始 policy 有 → 放行 → oracle: valid
 *   - u:object_r:magisk_file:s0       原始 policy 无 → -EINVAL → oracle: invalid ✓
 */

#include "selinux_hide.h"

#include <baselib.h>
#include <common.h>
#include <hook.h>
#include <kallsyms.h>
#include <ksyms.h>
#include <kputils.h>
#include <log.h>
#include <linux/security/selinux/include/security.h>
#include <linux/security.h>
#include <uapi/asm-generic/errno.h>

#include <linux/fs.h>
#include <linux/vmalloc.h>

#define KP_APP_UID_MIN        10000
#define KP_DENY_ALL           "0 ffffffff 0 ffffffff 0 0"
#define KP_TYPE_NAME_MAX      255
#define KP_POLICY_MAGIC       0xf97cff8c
#define KP_POLICY_STRING      "SE Linux"
#define KP_VERS_NEW           24   /* >= 24 使用新 header 布局 */

#ifndef GFP_ATOMIC
#define KP_GFP                ((gfp_t)0)
#else
#define KP_GFP                GFP_ATOMIC
#endif

enum kp_sel_inos {
    SEL_CONTEXT = 5,
    SEL_ACCESS  = 6,
};

/*
 * write_op[5] / write_op[6] 原型：ssize_t (*)(struct file *, char *, size_t)
 */
typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);

typedef int (*kp_ctx_to_sid_policy_fn)(struct selinux_policy *, const char *, u32, u32 *, u32, gfp_t);

/*
 * 运行时状态
 */
static struct kp_hide_state {
    bool        hooks_installed;
    write_op_fn orig_context_write;
    write_op_fn orig_access_write;
    void       *orig_setprocattr;
    int         setprocattr_argno;
    void       *policy_backup_raw;
    size_t      policy_backup_len;
    u32         policy_backup_vers;
    struct selinux_load_state policy_load_state;
} g_hide;

static kp_ctx_to_sid_policy_fn g_context_to_sid_with_policy;

/* ===================== 工具函数 ===================== */

static u32 kp_get_le32(const void *ptr)
{
    const u8 *p = ptr;
    return ((u32)p[0]) | ((u32)p[1] << 8) |
           ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static bool kp_isspace(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
}

/*
 * 验证 policydb header（magic + "SE Linux" + version）
 * 提取 version 用于判断 datum 布局
 */
static int kp_parse_policy_header(const void *data, size_t len, u32 *vers_out)
{
    const u8 *p        = (const u8 *)data;
    u32       magic;
    u32       magic_len;
    size_t    vers_off;

    if (!data || !vers_out || len < 20)
        return -EINVAL;

    magic = kp_get_le32(p);
    if (magic != KP_POLICY_MAGIC)
        return -EINVAL;

    magic_len = kp_get_le32(p + 4);
    if (magic_len != lib_strlen(KP_POLICY_STRING))
        return -EINVAL;

    if (8 + magic_len + sizeof(u32) > len)
        return -EINVAL;

    if (lib_memcmp(p + 8, KP_POLICY_STRING, magic_len))
        return -EINVAL;

    vers_off = 8 + magic_len;
    *vers_out = kp_get_le32(p + vers_off);
    return 0;
}

/*
 * 从 context 字符串中提取 type 段
 * context 格式: user:role:type:sensitivity[:categories]
 * 示例: u:r:app_zygote:s0:c512,c768
 */
static int kp_extract_type(const char *ctx, size_t len,
                           const char **type, size_t *type_len)
{
    const char *p      = ctx;
    const char *end    = ctx + len;
    const char *start;
    int         colons = 0;

    if (!ctx || !type || !type_len || !len)
        return -EINVAL;

    /* 跳过末尾空白 */
    while (end > ctx && (kp_isspace(end[-1]) || end[-1] == '\0'))
        end--;

    /* 找第 2 个冒号后的 type 段 */
    while (p < end && colons < 2) {
        if (*p == ':')
            colons++;
        p++;
    }
    if (colons < 2)
        return -EINVAL;

    /* p 已经指向 type 起始 */
    start = p;
    while (p < end && *p != ':')
        p++;

    if (p == start)
        return -EINVAL;

    *type     = start;
    *type_len = p - start;
    return 0;
}

/*
 * 检查命中点是否是一个有效的 type datum
 *
 * policydb type datum 结构（头部字段）:
 *   旧版 (< VER24): u32 len; u32 value; u32 primary; name
 *   新版 (>= VER24): u32 len; u32 value; u32 properties; u32 bounds; name
 *
 * 命中点 offset 指向 type datum 的 name 字符串起始位置。
 * 我们检查 name 前面的字段是否符合预期。
 *
 * @base  policydb base
 * @off   type name 字符串在 policydb 中的 offset
 * @name_len  期望的 type name 长度
 */
static bool kp_type_record_matches(const u8 *base, size_t off, size_t name_len)
{
    u32 len32, val32, props32;

    if (g_hide.policy_backup_vers >= KP_VERS_NEW) {
        /* 新版 layout: len, value, properties, bounds, name */
        if (off < 16)
            return false;

        len32   = kp_get_le32(base + off - 16);
        val32   = kp_get_le32(base + off - 12);
        props32 = kp_get_le32(base + off - 8);
    } else {
        /* 旧版 layout: len, value, primary, name */
        if (off < 12)
            return false;

        len32   = kp_get_le32(base + off - 12);
        val32   = kp_get_le32(base + off - 8);
        props32 = kp_get_le32(base + off - 4);
    }

    /* len 必须与 type 名长度一致 */
    if (len32 != name_len)
        return false;

    /* value 必须非零（有效 type value） */
    if (val32 == 0)
        return false;

    if (g_hide.policy_backup_vers >= KP_VERS_NEW) {
        /* 新版 properties: 必须是 primary type，不能是 attribute */
        if (!(props32 & 0x0001))
            return false;
        if (props32 & 0x0002)
            return false;
    } else {
        /* 旧版 primary 字段必须非零 */
        if (props32 == 0)
            return false;
    }

    return true;
}

/*
 * 从原始 policydb backup 中查找 type 是否存在
 *
 * 策略：使用 lib_memmem 在二进制 policydb 中搜索 type name 字符串，
 * 然后验证命中的位置是否真的是一个有效的 type datum 头部。
 * 正确命中的特征：type name 前面的 name_len 字段等于期望长度。
 *
 * 这样不需要解析完整的 policydb 结构（二进制格式复杂且版本相关），
 * 只需验证"名字出现在正确的结构中"即可。
 */
static bool kp_type_exists_in_backup(const char *type, size_t type_len)
{
    const u8 *base = (const u8 *)g_hide.policy_backup_raw;
    size_t    pos  = 0;

    if (!base || !g_hide.policy_backup_len ||
        !type || !type_len || type_len > KP_TYPE_NAME_MAX)
        return false;

    while (pos < g_hide.policy_backup_len) {
        void *hit;

        hit = lib_memmem(base + pos,
                         g_hide.policy_backup_len - pos,
                         type, type_len);
        if (!hit)
            return false;

        if (kp_type_record_matches(base,
                                   (size_t)((u8 *)hit - base),
                                   (u32)type_len))
            return true;

        pos = ((u8 *)hit - base) + 1;
    }
    return false;
}

/*
 * 解析 policy-aware context_to_sid 符号。
 * 只有 policy-aware API 可用时才启用；旧内核退回二进制 fallback。
 */
static void kp_prepare_policy_symbols(void)
{
    if (!g_context_to_sid_with_policy)
        g_context_to_sid_with_policy =
            (kp_ctx_to_sid_policy_fn)kallsyms_lookup_name("security_context_to_sid_with_policy");
}

/*
 * 用 backup 策略对象做 context → SID 转换
 * 只有 policy-aware API 可用时才启用；旧内核退回二进制 fallback。
 */
static int kp_context_to_sid_backup(const char *scontext, u32 scontext_len,
                                    u32 *out_sid, gfp_t gfp)
{
    if (!g_hide.policy_load_state.policy)
        return -ENODATA;

    kp_prepare_policy_symbols();

    if (!g_context_to_sid_with_policy)
        return -ENOSYS;

    return g_context_to_sid_with_policy(g_hide.policy_load_state.policy,
                                        scontext, scontext_len, out_sid,
                                        SECSID_NULL, gfp);
}

/*
 * 检查 context 是否在原始策略中有效。
 *
 * 优先使用 policy 对象做精确验证（security_context_to_sid），
 * 不可用时退回二进制 type 搜索（fallback）。
 */
static bool kp_context_valid(const char *ctx, size_t len)
{
    const char *type     = NULL;
    size_t      type_len = 0;
    u32         sid      = SECSID_NULL;
    int         ret;

    if (!ctx || !len || len > 0xffffffffU)
        return false;

    /* 优先：policy 对象验证 */
    if (g_hide.policy_load_state.policy) {
        ret = kp_context_to_sid_backup(ctx, (u32)len, &sid, KP_GFP);
        if (!ret && sid != SECSID_NULL)
            return true;
        /* -ENOSYS 表示函数指针不可用，fallback */
        if (ret != -ENOSYS)
            return false;
    }

    /* fallback：二进制搜索 */
    if (kp_extract_type(ctx, len, &type, &type_len))
        return false;
    return kp_type_exists_in_backup(type, type_len);
}

/*
 * 解析 access 字符串的下一个 token
 * access 格式: "scon tcon tclass x01 x02 x03 x04 x05 x06"
 */
static int kp_next_token(const char **cursor, const char *end,
                         const char **token, size_t *token_len)
{
    const char *p = *cursor;

    while (p < end && kp_isspace(*p))
        p++;

    if (p >= end || *p == '\0')
        return -EINVAL;

    *token     = p;
    *token_len = 0;
    while (p < end && !kp_isspace(*p) && *p != '\0') {
        p++;
        (*token_len)++;
    }
    *cursor = p;
    return 0;
}

/*
 * 检查 access 请求中 scon/tcon 的 type 是否都在原始 backup 中存在
 */
static bool kp_access_valid_in_backup(const char *buf, size_t size)
{
    const char *scon     = NULL;
    const char *tcon     = NULL;
    size_t      scon_len = 0;
    size_t      tcon_len = 0;
    const char *cursor   = buf;
    const char *end      = buf + size;

    if (!buf || !size)
        return false;

    if (kp_next_token(&cursor, end, &scon, &scon_len))
        return false;
    if (kp_next_token(&cursor, end, &tcon, &tcon_len))
        return false;

    return kp_context_valid(scon, scon_len) && kp_context_valid(tcon, tcon_len);
}

/* ===================== Hook 函数 ===================== */

/*
 * write_op[5] 前置 hook: context write
 * type 不在原始 policy backup → 返回 -EINVAL（kernel 告诉 app: invalid context）
 */
static void before_write_context(hook_fargs3_t *args, void *udata)
{
    char  *buf  = (char *)args->arg1;
    size_t size = (size_t)args->arg2;

    /* 仅拦截 app 进程 */
    if (current_uid() < KP_APP_UID_MIN)
        return;

    if (!g_hide.policy_load_state.policy && !g_hide.policy_backup_raw)
        return;

    if (kp_context_valid(buf, size))
        return;

    /* type 不在原始 policy，是后来 inject 的，拦截 */
    args->ret         = -EINVAL;
    args->skip_origin = 1;
}

/*
 * write_op[6] 前置 hook: access write
 * scon 或 tcon 的 type 不在原始 backup → 返回 deny-all decision
 */
static void before_write_access(hook_fargs3_t *args, void *udata)
{
    char  *buf        = (char *)args->arg1;
    size_t  size       = (size_t)args->arg2;
    size_t  denied_len = sizeof(KP_DENY_ALL) - 1;

    if (current_uid() < KP_APP_UID_MIN)
        return;

    if (!g_hide.policy_load_state.policy && !g_hide.policy_backup_raw)
        return;

    if (kp_access_valid_in_backup(buf, size))
        return;

    /* 写入空间不足时直接返回错误 */
    if (size < denied_len + 1) {
        args->ret         = -EINVAL;
        args->skip_origin = 1;
        return;
    }

    lib_memcpy(buf, KP_DENY_ALL, denied_len);
    buf[denied_len] = '\0';
    args->ret         = denied_len;
    args->skip_origin = 1;
}

/*
 * security_setprocattr 前置 hook
 * 过滤 /proc/self/attr/current 写入（app 进程尝试设置 SELinux context）
 *
 * security_setprocattr(lsm, name, value, size)
 *   lsm="selinux", name="current" 时拦截非法 context
 */
static void kp_handle_setprocattr(const char *name, void *value, size_t size,
                                  hook_fargs0_t *args)
{
    if (current_uid() < KP_APP_UID_MIN)
        return;

    if (!name || lib_strcmp(name, "current"))
        return;

    if (!g_hide.policy_load_state.policy && !g_hide.policy_backup_raw)
        return;

    if (kp_context_valid((const char *)value, size))
        return;

    args->ret         = -EINVAL;
    args->skip_origin = 1;
}

static bool kp_lsm_arg_matches_selinux(unsigned long lsm_arg)
{
    const char *lsm;

    if (!lsm_arg)
        return true;

    /*
     * 新内核可能传 int lsmid 而不是 const char *lsm。
     * 小整数不能当指针解引用；这种情况下只按 name=current 过滤。
     */
    if (lsm_arg < 4096)
        return true;

    lsm = (const char *)lsm_arg;
    return !lsm[0] || !lib_strcmp(lsm, "selinux");
}

static void before_setprocattr3(hook_fargs3_t *args, void *udata)
{
    kp_handle_setprocattr((const char *)args->arg0,
                          (void *)args->arg1,
                          (size_t)args->arg2,
                          (hook_fargs0_t *)args);
}

static void before_setprocattr4(hook_fargs4_t *args, void *udata)
{
    if (!kp_lsm_arg_matches_selinux((unsigned long)args->arg0))
        return;

    kp_handle_setprocattr((const char *)args->arg1,
                          (void *)args->arg2,
                          (size_t)args->arg3,
                          (hook_fargs0_t *)args);
}

static bool kp_setprocattr_has_lsm_arg(void)
{
    return kver >= VERSION(6, 1, 0);
}

/* ===================== Policy Backup ===================== */

/*
 * 释放已加载的策略对象
 */
static void kp_cancel_load_state(struct selinux_load_state *load_state)
{
    if (!load_state || !load_state->policy)
        return;

    if (kfunc(selinux_policy_cancel)) {
        if (selinux_need_call_compat() && !kvar(selinux_state)) {
            lib_memset(load_state, 0, sizeof(*load_state));
            return;
        }

        if (selinux_need_call_compat())
            ((selinux_compat_kf_selinux_policy_cancel_t)kfunc(selinux_policy_cancel))(
                kvar(selinux_state), load_state);
        else
            kfunc(selinux_policy_cancel)(load_state);
    }

    lib_memset(load_state, 0, sizeof(*load_state));
}

/*
 * 从原始策略二进制解析出策略对象
 * 对象仅用于验证，不提交到运行策略
 */
static int kp_load_policy_object(void *data, size_t len)
{
    struct selinux_load_state load_state;
    int ret;

    kp_prepare_policy_symbols();

    if (!g_context_to_sid_with_policy)
        return -ENOSYS;

    if (!kfunc(security_load_policy) || !kfunc(selinux_policy_cancel))
        return -ENOSYS;

    if (selinux_need_call_compat() && !kvar(selinux_state))
        return -ENOSYS;

    lib_memset(&load_state, 0, sizeof(load_state));

    ret = security_load_policy(data, len, &load_state);
    if (ret || !load_state.policy) {
        if (load_state.policy)
            kp_cancel_load_state(&load_state);
        return ret ? ret : -EINVAL;
    }

    g_hide.policy_load_state = load_state;
    return 0;
}

/*
 * 通过 security_read_policy() 备份原始 Android sepolicy
 *
 * security_read_policy() 是 KernelPatch 已有的 compat wrapper：
 *   - 4.14 (kver < 4.17): 直接调用 security_read_policy(data, len)
 *   - 4.19 (4.17 <= kver < 6.4): 调用 compat 版本加 selinux_state
 *   - 6.x (kver >= 6.4): 直接调用 security_read_policy(data, len)
 */
static int kp_backup_policy(void)
{
    void *data = NULL;
    size_t len  = 0;
    u32    vers = 0;
    int    ret;

    if (g_hide.policy_backup_raw && g_hide.policy_backup_len)
        return 0;

    ret = security_read_policy(&data, &len);
    if (ret || !data || !len) {
        log_boot("selinux_hide: read policy failed ret=%d len=%zu\n", ret, len);
        if (data)
            vfree(data);
        return ret ? ret : -ENODATA;
    }

    ret = kp_parse_policy_header(data, len, &vers);
    if (ret) {
        log_boot("selinux_hide: invalid policy header: %d\n", ret);
        vfree(data);
        return ret;
    }

    g_hide.policy_backup_raw  = data;
    g_hide.policy_backup_len  = len;
    g_hide.policy_backup_vers = vers;

    /* 尝试解析为策略对象 */
    ret = kp_load_policy_object(data, len);
    if (ret) {
        log_boot("selinux_hide: load policy object failed ret=%d, fallback raw\n", ret);
    } else {
        log_boot("selinux_hide: policy object loaded=%llx\n",
                 (unsigned long long)g_hide.policy_load_state.policy);
    }

    log_boot("selinux_hide: policy backed up size=%zu vers=%u\n", len, vers);
    return 0;
}

static void kp_free_policy_backup(void)
{
    kp_cancel_load_state(&g_hide.policy_load_state);

    if (g_hide.policy_backup_raw) {
        vfree(g_hide.policy_backup_raw);
        g_hide.policy_backup_raw  = NULL;
        g_hide.policy_backup_len  = 0;
        g_hide.policy_backup_vers = 0;
    }
}

/* ===================== Hook 安装 ===================== */

/*
 * 安装 write_op[5] / write_op[6] inline hook
 */
static int kp_selinux_hide_install_hooks(void)
{
    hook_err_t  err;
    write_op_fn *write_op = NULL;

    if (g_hide.hooks_installed)
        return 0;

    /* 先备份原始 policy */
    err = kp_backup_policy();
    if (err) {
        log_boot("selinux_hide: backup failed: %d\n", err);
        return err;
    }

    write_op = (write_op_fn *)kallsyms_lookup_name("write_op");
    if (!write_op) {
        log_boot("selinux_hide: write_op not found\n");
        kp_free_policy_backup();
        return -ENOSYS;
    }

    g_hide.orig_context_write = write_op[SEL_CONTEXT];
    g_hide.orig_access_write  = write_op[SEL_ACCESS];

    if (!g_hide.orig_context_write || !g_hide.orig_access_write) {
        log_boot("selinux_hide: invalid write_op (NULL)\n");
        kp_free_policy_backup();
        return -EINVAL;
    }

    err = hook_wrap3((void *)g_hide.orig_context_write,
                     before_write_context, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        log_boot("selinux_hide: hook context failed: %d\n", err);
        kp_free_policy_backup();
        return -EINVAL;
    }

    err = hook_wrap3((void *)g_hide.orig_access_write,
                     before_write_access, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        log_boot("selinux_hide: hook access failed: %d\n", err);
        hook_unwrap((void *)g_hide.orig_context_write,
                    before_write_context, NULL);
        kp_free_policy_backup();
        return -EINVAL;
    }

    /* hook security_setprocattr (过滤 /proc/self/attr/current 写入) */
    {
        void *setprocattr = (void *)kfunc(security_setprocattr);
        if (!setprocattr)
            setprocattr = (void *)kallsyms_lookup_name("security_setprocattr");

        if (setprocattr) {
            if (kp_setprocattr_has_lsm_arg()) {
                err = hook_wrap4(setprocattr, before_setprocattr4, NULL, NULL);
                if (err == HOOK_NO_ERR)
                    g_hide.setprocattr_argno = 4;
            } else {
                err = hook_wrap3(setprocattr, before_setprocattr3, NULL, NULL);
                if (err == HOOK_NO_ERR)
                    g_hide.setprocattr_argno = 3;
            }

            if (err == HOOK_NO_ERR) {
                g_hide.orig_setprocattr = setprocattr;
                log_boot("selinux_hide: setprocattr hook installed\n");
            } else {
                log_boot("selinux_hide: hook setprocattr failed: %d\n", err);
            }
        }
    }

    g_hide.hooks_installed = true;
    log_boot("selinux_hide: hooks installed\n");
    return 0;
}

int kpatch_selinux_hide_init(void)
{
    return kpatch_selinux_hide_prepare();
}

int kpatch_selinux_hide_prepare(void)
{
    return kp_selinux_hide_install_hooks();
}

void kpatch_selinux_hide_exit(void)
{
    if (g_hide.hooks_installed) {
        if (g_hide.orig_context_write)
            hook_unwrap((void *)g_hide.orig_context_write,
                        before_write_context, NULL);
        if (g_hide.orig_access_write)
            hook_unwrap((void *)g_hide.orig_access_write,
                        before_write_access, NULL);
        if (g_hide.orig_setprocattr)
            hook_unwrap(g_hide.orig_setprocattr,
                        g_hide.setprocattr_argno == 3 ?
                        (void *)before_setprocattr3 :
                        (void *)before_setprocattr4,
                        NULL);
    }

    kp_free_policy_backup();
    lib_memset(&g_hide, 0, sizeof(g_hide));
    log_boot("selinux_hide: exited\n");
}