#define __section(X) __attribute__((section(X), used))
#define __noinline __attribute__((noinline))

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
