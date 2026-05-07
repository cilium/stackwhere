// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#define __section(X) __attribute__((section(X), used))
#define __always_inline inline __attribute__((always_inline))

struct __sk_buff
{
    unsigned long long dummy; // just to make sure the struct is not empty
};

// The object file should produce the following output from the test:
// TestGetStackSlotUsage expects 3 stack slot groups for cil_entry:
// Slot group 0: a (32 bytes), b (32 bytes), c (32 bytes)
// Slot group 1: two_inlined_a (16 bytes), two_inlined_b (16 bytes), two_inlined_c (16 bytes)
// Slot group 2: one_inlined_d (8 bytes)

struct four
{
    unsigned long long a;
    unsigned long long b;
    unsigned long long c;
    unsigned long long d;
};

struct two
{
    unsigned long long a;
    unsigned long long b;
};

// An ASM block, with no actual instructions, but we tell the compiler that we need to have the
// address of x in a register. And the only way to get the address of x is to put it on the stack.
// This forces the compiler to put x on the stack, even if it could have otherwise optimized it away
// or kept it in registers.
#define force_on_stack(x) asm volatile("" ::"r"(&x))

void __always_inline inlined_d()
{
    unsigned long long one_inlined_d = 0;
    force_on_stack(one_inlined_d);
}

void __always_inline inlined_c()
{
    struct two two_inlined_c = {};
    force_on_stack(two_inlined_c);
    // `two_inlined_c` is never used after this point, but `inlined_d` will use a new stack slot
    // anyway because the "lifetime" of `two_inlined_c` ends at the end of the function.
    // So the compiler will use more stack space here than technically needed.
    inlined_d();
}

void __always_inline inlined_b()
{
    struct two two_inlined_b = {};
    force_on_stack(two_inlined_b);
}

void __always_inline inlined_a()
{
    struct two two_inlined_a = {};
    force_on_stack(two_inlined_a);
}

__section("tc") int cil_entry(struct __sk_buff *ctx)
{
    {
        // a will live on the stack until the end of the scope, so inlined_a and inlined_b
        // cannot reuse its stack space. But inlined_b can reuse the stack space of
        // inlined_a.
        struct four a = {};
        force_on_stack(a);
        inlined_a();
        inlined_b();
    }

    // Variables in this scope can reuse the stack space of a, inlined_a, and inlined_b.
    // So `b`, `two_inlined_a` and `two_inlined_b` will be placed on the same stack slots as
    // those used above.
    {
        struct four b = {};
        force_on_stack(b);
        inlined_a();
        inlined_b();
    }

    // `c` will fit over stack used by `a` and `b`.
    {
        struct four c = {};
        force_on_stack(c);
        // `inlined_c` calls `inlined_d` before the end of its function, and thus `inlined_d`
        // will use an additional stack slot.
        inlined_c();
    }
    return 0;
}
