#include <stdio.h>
#include <linux/bpf.h>
#include <bpf.h>
#include <libbpf.h>
#include <signal.h>
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
	int status, res = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [BPF program]\n", argv[0]);
		return -1;
	}

	obj = bpf_object__open(argv[1]);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 1;
	}
	
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_title(obj, "sigfilter");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		goto cleanup;
	}

		
	fd = bpf_program__fd(prog);
	if (fd < 0) {
		fprintf(stderr, "ERROR: unable to get fd\n");
		goto cleanup;
	}

	/* sync only */
	if (pipe(p) == -1) {
		perror("pipe");
		goto cleanup;
	}

	switch (pid = fork()) {
		case 0:
			/* sync */
			if (close(p[1]) < 0)
				fatal("close in");

			if (read(p[0], &buf, 1) < 0)
				fatal("read");

			if (close(p[0]) < 0)
				fatal("close out");

			__asm__("int3\n");
			return 0;
			break;
		case -1:
			fprintf(stderr, "Fork error\n");
			goto cleanup;
			
		default:
			break;
	}

	if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
		perror("attach");
		goto cleanup;
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		goto cleanup;
	}

	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
		fprintf(stderr, "unexpected wait status: %x", status);
		goto cleanup;
	}

	if (ptrace(0x420f, pid, (void*) 0, (void*) fd) == -1) {
		perror("ptrace");
		goto cleanup;
	}

	if (close(p[1]) < 0 || close(p[0]) < 0) {
		perror("close in parent");
		goto cleanup;
	}

	if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
		perror("cont");
		goto cleanup;
	}

	if (wait(&res) < 0) {
		perror("wait");
		res = -1;
	}	

	if (res == 0)
		printf("OK\n");
	else
		printf("FAIL\n");

cleanup:
	bpf_object__close(obj);
	return res;
}
