#include "sigfilter.h"

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	uint64_t old, new, validate, ptr;
	int res = 42;

	if (bpf_getregset(NT_PRSTATUS, REG64_RSP, &ptr, sizeof(ptr)) != 0)
		return 0;

	/* try write & restore */
	if (bpf_copy_from_user(&old, sizeof(old), ptr) != 0)
		return 0;

	new = old + 0x2;
	if (bpf_copy_to_user(ptr, &new, sizeof(new)) != 0)
		return 0;

	if (bpf_copy_from_user(&validate, sizeof(validate), ptr) != 0)
		return 0;

	if (validate != new)
		res = 0;

	if (bpf_copy_to_user(ptr, &old, sizeof(old)) != 0)
		return 0;



	
	return res;
}


char _license[] SEC("license") = "GPL";
