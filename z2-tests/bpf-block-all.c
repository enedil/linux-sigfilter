#include "sigfilter.h"


SEC("sigfilter")
int bpf_sigfilter(struct siginfo64 *ctx) {
	return 42;
}


char _license[] SEC("license") = "GPL";
