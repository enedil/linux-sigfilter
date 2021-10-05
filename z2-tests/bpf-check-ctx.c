#include "sigfilter.h"

SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	char *test = (char*) &ctx[1000];
	/* access should be blocked */
	if (*test == 1)
		return 0;
	return 42;
}


char _license[] SEC("license") = "GPL";
