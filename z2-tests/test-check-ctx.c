#include <stdio.h>
#include <linux/bpf.h>
#include <bpf.h>
#include <signal.h>
#include <libbpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>

void fatal(char *m) {
	perror(m);
	exit(-1);
}


int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	long long  fd;
	int p[2];
	char buf;
	pid_t pid;
	int res = 1;

	obj = bpf_object__open("bpf-check-ctx.o");
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 1;
	}
	
	if (bpf_object__load(obj)) {
		res = 0;
		printf("OK\n");
	}
	else
		printf("FAIL\n");

	bpf_object__close(obj);
	return res;
}
