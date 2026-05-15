/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux Hide - clean policy type oracle
 *
 * 保存用户态修改前的 policy bytes；app 查询新增 type 时按 clean policy 视角返回无效。
 */

#include "selinux_hide.h"

#include <baselib.h>
#include <common.h>
#include <hook.h>
#include <kallsyms.h>
#include <kputils.h>
#include <log.h>
#include <uapi/asm-generic/errno.h>

#include <asm/current.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <security/selinux/include/security.h>

#define KP_APP_UID_MIN 10000
#define KP_CONTEXT_MAX 512
#define KP_TYPE_NAME_MAX 255
#define KP_POLICY_MAGIC 0xf97cff8c
#define KP_POLICY_STRING "SE Linux"
#define KP_POLICYDB_VERSION_BOUNDARY 24
#define KP_TYPEDATUM_PROPERTY_PRIMARY 0x0001
#define KP_TYPEDATUM_PROPERTY_ATTRIBUTE 0x0002

enum kp_sel_inos {
    SEL_CONTEXT = 5,
    SEL_ACCESS = 6,
};

typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);

struct kp_clean_policy {
    void *data;
    size_t len;
    u32 policyvers;
    bool ready;
};

struct kp_selinux_hide_state {
    bool hooks_installed;
    write_op_fn orig_context_write;
    write_op_fn orig_access_write;
    struct kp_clean_policy clean;
};

static struct kp_selinux_hide_state g_hide;
static write_op_fn *g_write_op;

static bool kp_is_app_uid(void)
{
    return current_uid() >= KP_APP_UID_MIN;
}

static u32 kp_get_le32(const void *ptr)
{
    const u8 *p = ptr;

    return ((u32)p[0]) |
           ((u32)p[1] << 8) |
           ((u32)p[2] << 16) |
           ((u32)p[3] << 24);
}

static int kp_parse_policy_header(const void *data, size_t len, u32 *policyvers)
{
    const u8 *p = data;
    size_t magic_len;
    size_t vers_off;

    if (!data || !policyvers || len < 20)
        return -EINVAL;

    if (kp_get_le32(p) != KP_POLICY_MAGIC)
        return -EINVAL;

    magic_len = kp_get_le32(p + 4);
    if (magic_len != lib_strlen(KP_POLICY_STRING))
        return -EINVAL;

    if (8 + magic_len + sizeof(u32) > len)
        return -EINVAL;

    if (lib_memcmp(p + 8, KP_POLICY_STRING, magic_len))
        return -EINVAL;

    vers_off = 8 + magic_len;
    *policyvers = kp_get_le32(p + vers_off);
    return 0;
}

static int kp_save_clean_policy_bytes(void)
{
    void *policy = NULL;
    size_t policy_len = 0;
    u32 policyvers = 0;
    int rc;

    if (g_hide.clean.ready)
        return 0;

    if (!kfunc(security_read_policy) || !kfunc(kvfree)) {
        log_boot("selinux_hide: security_read_policy unavailable\n");
        return -ENOSYS;
    }

    if (selinux_need_call_compat() && !kvar(selinux_state)) {
        log_boot("selinux_hide: selinux_state unavailable\n");
        return -ENOSYS;
    }

    rc = security_read_policy(&policy, &policy_len);
    if (rc) {
        log_boot("selinux_hide: read clean policy failed: %d\n", rc);
        return rc;
    }

    rc = kp_parse_policy_header(policy, policy_len, &policyvers);
    if (rc) {
        log_boot("selinux_hide: invalid clean policy bytes: %d\n", rc);
        if (policy)
            kvfree(policy);
        return rc;
    }

    g_hide.clean.data = policy;
    g_hide.clean.len = policy_len;
    g_hide.clean.policyvers = policyvers;
    g_hide.clean.ready = true;

    log_boot("selinux_hide: clean policy saved, len=%zu, vers=%u\n", policy_len, policyvers);
    return 0;
}

static void kp_free_clean_policy_bytes(void)
{
    if (g_hide.clean.data)
        kvfree(g_hide.clean.data);

    lib_memset(&g_hide.clean, 0, sizeof(g_hide.clean));
}

static bool kp_type_record_matches(const u8 *base, size_t off, size_t type_len)
{
    u32 name_len;
    u32 value;
    u32 props;

    if (g_hide.clean.policyvers >= KP_POLICYDB_VERSION_BOUNDARY) {
        if (off < 16)
            return false;

        name_len = kp_get_le32(base + off - 16);
        value = kp_get_le32(base + off - 12);
        props = kp_get_le32(base + off - 8);

        if (name_len != type_len || !value)
            return false;

        if (!(props & KP_TYPEDATUM_PROPERTY_PRIMARY))
            return false;

        if (props & KP_TYPEDATUM_PROPERTY_ATTRIBUTE)
            return false;

        if (props & ~(KP_TYPEDATUM_PROPERTY_PRIMARY | KP_TYPEDATUM_PROPERTY_ATTRIBUTE))
            return false;

        return true;
    }

    if (off < 12)
        return false;

    name_len = kp_get_le32(base + off - 12);
    value = kp_get_le32(base + off - 8);
    props = kp_get_le32(base + off - 4);

    return name_len == type_len && value && props;
}

static bool kp_type_exists_in_clean_policy(const char *type, size_t type_len)
{
    const u8 *base = g_hide.clean.data;
    size_t pos = 0;

    if (!g_hide.clean.ready || !type || !type_len || type_len > KP_TYPE_NAME_MAX)
        return false;

    while (pos < g_hide.clean.len) {
        void *hit = lib_memmem(base + pos, g_hide.clean.len - pos, type, type_len);
        size_t off;

        if (!hit)
            return false;

        off = (const u8 *)hit - base;
        if (kp_type_record_matches(base, off, type_len))
            return true;

        pos = off + 1;
    }

    return false;
}

static int kp_extract_type_range(const char *ctx, size_t len, const char **type, size_t *type_len)
{
    const char *p = ctx;
    const char *end = ctx + len;
    const char *start;
    int colons = 0;

    if (!ctx || !type || !type_len || !len)
        return -EINVAL;

    while (end > ctx && (end[-1] == '\0' || end[-1] == '\n' || end[-1] == ' ' || end[-1] == '\t'))
        end--;

    while (p < end) {
        if (*p == ':') {
            colons++;
            if (colons == 2) {
                p++;
                break;
            }
        }
        p++;
    }

    if (colons != 2 || p >= end)
        return -EINVAL;

    start = p;
    while (p < end && *p != ':')
        p++;

    if (p == start)
        return -EINVAL;

    *type = start;
    *type_len = p - start;
    return 0;
}

static bool kp_context_has_unknown_type(const char *ctx, size_t len)
{
    const char *type;
    size_t type_len;

    if (kp_extract_type_range(ctx, len, &type, &type_len))
        return false;

    return !kp_type_exists_in_clean_policy(type, type_len);
}

static size_t kp_copy_token(char *dst, size_t dst_size, const char **cursor)
{
    const char *p = *cursor;
    size_t len = 0;

    while (*p == ' ' || *p == '\t' || *p == '\n')
        p++;

    while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
        if (len + 1 < dst_size)
            dst[len] = *p;
        len++;
        p++;
    }

    if (dst_size)
        dst[len < dst_size ? len : dst_size - 1] = '\0';

    *cursor = p;
    return len;
}

static bool kp_access_has_unknown_type(const char *buf, size_t size)
{
    char *input;
    char scon[KP_CONTEXT_MAX];
    char tcon[KP_CONTEXT_MAX];
    const char *cursor;
    size_t token_len;
    bool unknown;

    if (!buf || !size)
        return false;

    input = vmalloc(size + 1);
    if (!input)
        return false;

    lib_memcpy(input, buf, size);
    input[size] = '\0';
    lib_memset(scon, 0, sizeof(scon));
    lib_memset(tcon, 0, sizeof(tcon));

    cursor = input;
    token_len = kp_copy_token(scon, sizeof(scon), &cursor);
    if (!token_len || token_len >= sizeof(scon)) {
        unknown = false;
        goto out;
    }

    token_len = kp_copy_token(tcon, sizeof(tcon), &cursor);
    if (!token_len || token_len >= sizeof(tcon)) {
        unknown = false;
        goto out;
    }

    unknown = kp_context_has_unknown_type(scon, lib_strlen(scon)) ||
              kp_context_has_unknown_type(tcon, lib_strlen(tcon));

out:
    vfree(input);
    return unknown;
}

static void before_write_context(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg1;
    size_t size = (size_t)args->arg2;

    if (!kp_is_app_uid() || !g_hide.clean.ready)
        return;

    if (!kp_context_has_unknown_type(buf, size))
        return;

    args->ret = -EINVAL;
    args->skip_origin = 1;
}

static void before_write_access(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg1;
    size_t size = (size_t)args->arg2;
    const char *denied = "0 ffffffff 0 ffffffff 0 0";
    size_t denied_len;

    if (!kp_is_app_uid() || !g_hide.clean.ready)
        return;

    if (!kp_access_has_unknown_type(buf, size))
        return;

    denied_len = lib_strlen(denied);
    if (size < denied_len + 1) {
        args->ret = -EINVAL;
        args->skip_origin = 1;
        return;
    }

    lib_memcpy(buf, denied, denied_len);
    buf[denied_len] = '\0';
    args->ret = denied_len;
    args->skip_origin = 1;
}

static int kp_selinux_hide_install_hooks(void)
{
    hook_err_t err;

    if (g_hide.hooks_installed)
        return 0;

    g_write_op = (write_op_fn *)kallsyms_lookup_name("write_op");
    if (!g_write_op) {
        log_boot("selinux_hide: write_op not found\n");
        return -ENOSYS;
    }

    g_hide.orig_context_write = g_write_op[SEL_CONTEXT];
    g_hide.orig_access_write = g_write_op[SEL_ACCESS];

    if (!g_hide.orig_context_write || !g_hide.orig_access_write) {
        log_boot("selinux_hide: invalid write_op\n");
        return -EINVAL;
    }

    err = hook_wrap3((void *)g_hide.orig_context_write, before_write_context, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        log_boot("selinux_hide: hook context failed: %d\n", err);
        return -EINVAL;
    }

    err = hook_wrap3((void *)g_hide.orig_access_write, before_write_access, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        log_boot("selinux_hide: hook access failed: %d\n", err);
        hook_unwrap((void *)g_hide.orig_context_write, before_write_context, NULL);
        return -EINVAL;
    }

    g_hide.hooks_installed = true;
    log_boot("selinux_hide: context/access hooks installed\n");
    return 0;
}

int kpatch_selinux_hide_init(void)
{
    return kpatch_selinux_hide_prepare();
}

int kpatch_selinux_hide_prepare(void)
{
    int rc;

    rc = kp_save_clean_policy_bytes();
    if (rc)
        return rc;

    return kp_selinux_hide_install_hooks();
}

int kpatch_selinux_hide_start_enforce(void)
{
    return kpatch_selinux_hide_prepare();
}

void kpatch_selinux_hide_exit(void)
{
    if (g_hide.hooks_installed) {
        if (g_hide.orig_context_write)
            hook_unwrap((void *)g_hide.orig_context_write, before_write_context, NULL);

        if (g_hide.orig_access_write)
            hook_unwrap((void *)g_hide.orig_access_write, before_write_access, NULL);
    }

    kp_free_clean_policy_bytes();
    lib_memset(&g_hide, 0, sizeof(g_hide));
    log_boot("selinux_hide: exited\n");
}
