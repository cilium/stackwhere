// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define __section(X) __attribute__((section(X), used))

struct __sk_buff
{
    unsigned long long dummy;
};

// Force the compiler to materialize the variable on the stack.
#define force_on_stack(x) asm volatile("" ::"r"(&x))

struct two
{
    unsigned long long a;
    unsigned long long b;
};

__section("tc") int beta(struct __sk_buff *ctx)
{
    struct two tmp = {};
    force_on_stack(tmp);
    return 0;
}

__section("tc") int alpha(struct __sk_buff *ctx)
{
    struct two tmp = {};
    force_on_stack(tmp);
    return 0;
}
