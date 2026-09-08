// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define __section(X) __attribute__((section(X), used))

extern int cil_entry(void *ctx);

__section("tc") int caller(void *ctx)
{
	return cil_entry(ctx);
}
