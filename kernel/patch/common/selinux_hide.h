/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_SELINUX_HIDE_H_
#define _KP_SELINUX_HIDE_H_

int kpatch_selinux_hide_init(void);
int kpatch_selinux_hide_prepare(void);
void kpatch_selinux_hide_exit(void);

#endif
