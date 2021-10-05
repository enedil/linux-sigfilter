#include "sigfilter.h"

SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	char buf[15];
	if (bpf_getregset(0xdeadbeef, 0xdeadbeef, buf, sizeof(buf)) == 0)
		return 0;

	return 42;
}


char _license[] SEC("license") = "GPL";
