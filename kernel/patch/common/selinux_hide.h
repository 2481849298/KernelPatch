/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 KernelPatch Contributors
 * SELinux Hide - Virtualize SELinux queries for app UIDs
 * Based on KernelSU selinux_hide implementation
 */

#ifndef _KPATCH_SELINUX_HIDE_H_
#define _KPATCH_SELINUX_HIDE_H_

/**
 * kpatch_selinux_hide_init - Initialize SELinux hide functionality
 *
 * Hooks /sys/fs/selinux/context, /sys/fs/selinux/access, and setprocattr
 * to virtualize SELinux queries for app UIDs (>= 10000).
 *
 * Hidden contexts include:
 * - ksu, ksu_file
 * - magisk, magisk_file, magisk_log_file
 * - apatch, apatch_file
 * - lsposed, lsposed_file, lsposed_app
 * - kernelpatch, kpatch
 * - And other root-related custom domains/types
 *
 * Return: 0 on success, negative error code on failure
 */
int kpatch_selinux_hide_init(void);

/**
 * kpatch_selinux_hide_exit - Cleanup SELinux hide
 *
 * Removes all hooks and cleans up resources
 */
void kpatch_selinux_hide_exit(void);

#endif /* _KPATCH_SELINUX_HIDE_H_ */
