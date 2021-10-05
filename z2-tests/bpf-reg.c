#include "sigfilter.h"

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	uint64_t old, new, validate;
	int res = 42;
	if (ctx->si_signo != SIGTRAP)
		return 0;
	
	/* try write & restore on some regs */
	#pragma clang loop unroll(full)
	for (int i = 0; i < 13; i++) {
		if (bpf_getregset(NT_PRSTATUS, i * sizeof(old),  &old, sizeof(old)) != 0)
			return 0;

		new = 0xdeadbeef;
		if (new == old)
			new++;

		if (bpf_setregset(NT_PRSTATUS, i * sizeof(new),  &new, sizeof(new)) != 0)
			return 0;

		if (bpf_getregset(NT_PRSTATUS, i * sizeof(validate),  &validate, sizeof(validate)) != 0)
			res = 0;

		// restore
		if (bpf_setregset(NT_PRSTATUS, i * sizeof(old),  &old, sizeof(old)) != 0)
			return 0;

	}

	return res;
}


char _license[] SEC("license") = "GPL";
