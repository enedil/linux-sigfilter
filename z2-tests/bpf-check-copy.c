#include "sigfilter.h"

SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	char buf[15];
	memset(buf, 0x31, sizeof(buf));
	if (bpf_copy_to_user(0, buf, sizeof(buf)) > 0)
		return 0;

	return 42;
}


char _license[] SEC("license") = "GPL";
