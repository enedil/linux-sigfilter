#include "sigfilter.h"

SEC("sigfilter")
int bpf_sigfilter(struct siginfo32 *ctx) {
	char buf[16];
	if (bpf_getregset(NT_386_TLS, 0, buf, sizeof(buf)) != 0)
		return 0;

	return 42;
}


char _license[] SEC("license") = "GPL";
