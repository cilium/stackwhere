#define __section(X) __attribute__((section(X), used))
#define __noinline __attribute__((noinline))
#define force_on_stack(x) asm volatile("" :: "r"(&(x)))

static __noinline void helper(int *value)
{
	*value = 42;
}

__section("tc") int entry(void *ctx)
{
	int value = 0;

	helper(&value);
	return value;
}

__section("tc/known") int z_known(void *ctx)
{
	long value = 0;

	force_on_stack(value);
	return value;
}
