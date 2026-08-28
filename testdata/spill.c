#define __section(X) __attribute__((section(X), used))
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_ARRAY 1

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 16);
} example_map __section(".maps");

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static int (*const bpf_get_prandom_u32)(void) = (void *)7;

extern void use_int(int);

__always_inline int lookup_example_map(int key)
{
    int *value = bpf_map_lookup_elem(&example_map, &key);
    if (value)
        return *value;
    return -1;
}

__section("tc") int cil_entry(void *ctx)
{
    // Get a value, unknown at compile time, so cannot be optimized away.
    int a = bpf_get_prandom_u32();
    // Use in external function, this prevents the compiler from reordering, side effects unknown.
    use_int(a);
    // Lookup map value, which forces `key` to be stored on the stack
    int b = lookup_example_map(0);
    // Use the value to prevent reordering.
    use_int(b);
    // Clobber all registers, forcing spilling around this point.
    asm volatile("" ::: "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9");
    // Use A separately, otherwise "a+b" would be calculated before the clobber and its result be stored in the stack.
    use_int(a);
    // Now use both
    return a + b;
}

static __noinline int sum_five(int a, int b, int c, int d, int e)
{
    return a + b + c + d + e;
}

__section("tc/direct_spill") int direct_spill(void *ctx)
{
    return bpf_get_prandom_u32() + sum_five(
        bpf_get_prandom_u32(),
        bpf_get_prandom_u32(),
        bpf_get_prandom_u32(),
        bpf_get_prandom_u32(),
        bpf_get_prandom_u32());
}
