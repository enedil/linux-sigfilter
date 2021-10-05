#include "sigfilter.h"

SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	if (ctx->si_signo != SIGTRAP)
		return 0;

	return 42;
}


char _license[] SEC("license") = "GPL";
