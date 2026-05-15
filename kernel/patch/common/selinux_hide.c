/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux hide implementation for KernelPatch
 * Hide root-related SELinux contexts from app processes
 */

#include <ktypes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <ksyms.h>
#include <hook.h>
#include <predata.h>
#include <accctl.h>
#include <linux/string.h>

// SELinux write_op array indices
enum sel_inos {
    SEL_ROOT_INO = 2,
    SEL_LOAD,
    SEL_ENFORCE,
    SEL_CONTEXT,
    SEL_ACCESS,
    SEL_CREATE,
    SEL_RELABEL,
    SEL_USER,
    SEL_POLICYVERS,
    SEL_COMMIT_BOOLS,
    SEL_MLS,
    SEL_DISABLE,
    SEL_MEMBER,
    SEL_CHECKREQPROT,
    SEL_COMPAT_NET,
    SEL_REJECT_UNKNOWN,
    SEL_DENY_UNKNOWN,
    SEL_STATUS,
    SEL_POLICY,
    SEL_VALIDATE_TRANS,
    SEL_INO_NEXT,
};

typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);

static write_op_fn orig_context_write = NULL;
static write_op_fn orig_access_write = NULL;

// Check if string contains root-related keywords
// Returns 1 if sensitive keyword found, 0 otherwise
static int contains_sensitive_keyword(const char *buf, size_t size)
{
    if (!buf || size == 0)
        return 0;

    // Check for magisk-related contexts
    if (strstr(buf, "magisk")) return 1;

    // Check for KernelSU-related contexts
    if (strstr(buf, "ksu")) return 1;

    // Check for APatch-related contexts
    if (strstr(buf, "apatch")) return 1;

    // Check for su-related contexts
    if (strstr(buf, ":su:")) return 1;
    if (strstr(buf, "su_file")) return 1;

    // Check for lsposed-related contexts
    if (strstr(buf, "lsposed")) return 1;

    // Check for kernelpatch-related contexts
    if (strstr(buf, "kernelpatch")) return 1;
    if (strstr(buf, "kpatch")) return 1;

    return 0;
}

// Before hook for /sys/fs/selinux/context write
static void before_write_context(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg1;
    size_t size = (size_t)args->arg2;
    uid_t uid = current_uid();

    // Only filter for app processes (uid >= 10000)
    if (uid >= 10000) {
        // If sensitive keyword detected, return error (context not found)
        if (contains_sensitive_keyword(buf, size)) {
            args->ret = -EINVAL;
            args->skip_origin = true;
        }
    }
}

// Before hook for /sys/fs/selinux/access write
static void before_write_access(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg1;
    size_t size = (size_t)args->arg2;
    uid_t uid = current_uid();

    // Only filter for app processes (uid >= 10000)
    if (uid >= 10000) {
        // If sensitive keyword detected, return error (access denied)
        if (contains_sensitive_keyword(buf, size)) {
            args->ret = -EINVAL;
            args->skip_origin = true;
        }
    }
}

int kpatch_selinux_hide_init(void)
{
    unsigned long addr;
    hook_err_t err;

    log_boot("selinux_hide: initializing\n");

    // Lookup write_op array
    addr = kallsyms_lookup_name("write_op");
    if (!addr) {
        log_boot("selinux_hide: write_op not found\n");
        return -1;
    }

    write_op_fn *selinux_write_op = (write_op_fn *)addr;

    // Save original function pointers
    orig_context_write = selinux_write_op[SEL_CONTEXT];
    orig_access_write = selinux_write_op[SEL_ACCESS];

    if (!orig_context_write || !orig_access_write) {
        log_boot("selinux_hide: invalid write_op functions\n");
        return -1;
    }

    log_boot("selinux_hide: orig_context_write=%llx\n", (unsigned long long)orig_context_write);
    log_boot("selinux_hide: orig_access_write=%llx\n", (unsigned long long)orig_access_write);

    // Hook context write using hook_wrap3 (3 arguments: file, buf, size)
    err = hook_wrap3((void *)orig_context_write, before_write_context, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        log_boot("selinux_hide: hook context_write failed: %d\n", err);
        return -1;
    }

    // Hook access write using hook_wrap3 (3 arguments: file, buf, size)
    err = hook_wrap3((void *)orig_access_write, before_write_access, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        log_boot("selinux_hide: hook access_write failed: %d\n", err);
        // Unhook context_write on failure
        unhook((void *)orig_context_write);
        return -1;
    }

    log_boot("selinux_hide: initialized successfully\n");
    return 0;
}
