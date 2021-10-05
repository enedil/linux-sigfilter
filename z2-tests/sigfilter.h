#ifndef SIGFILTER_H
#define SIGFILTER_H

#include <stdint.h>
#include <stddef.h>

#define SEC(s) __attribute__((section(s)))

enum {
	SIGHUP = 1,
	SIGINT = 2,
	SIGQUIT = 3,
	SIGILL = 4,
	SIGTRAP = 5,
	SIGABRT = 6,
	SIGBUS = 7,
	SIGFPE = 8,
	SIGKILL = 9,
	SIGUSR1 = 10,
	SIGSEGV = 11,
	SIGUSR2 = 12,
	SIGPIPE = 13,
	SIGALRM = 14,
	SIGTERM = 15,
	SIGSTKFLT = 16,
	SIGCHLD = 17,
	SIGCONT = 18,
	SIGSTOP = 19,
	SIGTSTP = 20,
	SIGTTIN = 21,
	SIGTTOU = 22,
	SIGURG = 23,
	SIGXCPU = 24,
	SIGXFSZ = 25,
	SIGVTALRM = 26,
	SIGPROF = 27,
	SIGWINCH = 28,
	SIGPOLL = 29,
	SIGPWR = 30,
	SIGSYS = 31,
	SIGRTMIN = 32,
	SIGRTMAX = 63,
};

union sigval32 {
	int sival_int;
	uint32_t sival_ptr;
};

union sigval64 {
	int sival_int;
	uint64_t sival_ptr;
};

struct siginfo32 {
	union {
		struct {
			int si_signo;
			int si_errno;
			int si_code;
			union {
				struct {
					union {
						struct {
							int si_pid;
							int si_uid;
						};
						struct {
							int si_tid;
							int si_overrun;
						};
					};
					union {
						union sigval32 si_value;
						struct {
							int si_status;
							int si_utime;
							int si_stime;

						};
					};
				};
				struct {
					uint32_t si_addr;
					short si_addr_lsb;
					union {
						struct {
							uint32_t si_lower;
							uint32_t si_upper;
						};
						uint32_t si_pkey;
					};
				};
				struct {
					int si_band;
					int si_fd;
				};
				struct {
					uint32_t si_call_addr;
					int si_syscall;
					unsigned si_arch;
				};
			};
		};
		int _pad[32];
	};
};

struct siginfo64 {
	union {
		struct {
			int si_signo;
			int si_errno;
			int si_code;
			union {
				struct {
					union {
						struct {
							int si_pid;
							int si_uid;
						};
						struct {
							int si_tid;
							int si_overrun;
						};
					};
					union {
						struct {
							union sigval64 si_value;
							int si_sys_private;
						};
						struct {
							int si_status;
							long long si_utime;
							long long si_stime;

						};
					};
				};
				struct {
					uint64_t si_addr;
					short si_addr_lsb;
					union {
						struct {
							uint64_t si_lower;
							uint64_t si_upper;
						};
						uint32_t si_pkey;
					};
				};
				struct {
					long long si_band;
					int si_fd;
				};
				struct {
					uint64_t si_call_addr;
					int si_syscall;
					unsigned si_arch;
				};
			};
		};
		int _pad[32];
	};
};

_Static_assert(offsetof(struct siginfo64, si_signo) == 0, "fail");
_Static_assert(offsetof(struct siginfo64, si_errno) == 4, "fail");
_Static_assert(offsetof(struct siginfo64, si_code) == 8, "fail");
_Static_assert(offsetof(struct siginfo32, si_signo) == 0, "fail");
_Static_assert(offsetof(struct siginfo32, si_errno) == 4, "fail");
_Static_assert(offsetof(struct siginfo32, si_code) == 8, "fail");

_Static_assert(offsetof(struct siginfo64, si_tid) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo64, si_overrun) == 0x14, "fail");
_Static_assert(offsetof(struct siginfo64, si_value) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo32, si_tid) == 0x0C, "fail");
_Static_assert(offsetof(struct siginfo32, si_overrun) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo32, si_value) == 0x14, "fail");

_Static_assert(offsetof(struct siginfo64, si_pid) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo64, si_uid) == 0x14, "fail");
_Static_assert(offsetof(struct siginfo64, si_value) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo32, si_pid) == 0x0C, "fail");
_Static_assert(offsetof(struct siginfo32, si_uid) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo32, si_value) == 0x14, "fail");

_Static_assert(offsetof(struct siginfo64, si_pid) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo64, si_uid) == 0x14, "fail");
_Static_assert(offsetof(struct siginfo64, si_status) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo64, si_utime) == 0x20, "fail");
_Static_assert(offsetof(struct siginfo64, si_stime) == 0x28, "fail");
_Static_assert(offsetof(struct siginfo32, si_pid) == 0x0C, "fail");
_Static_assert(offsetof(struct siginfo32, si_uid) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo32, si_status) == 0x14, "fail");
_Static_assert(offsetof(struct siginfo32, si_utime) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo32, si_stime) == 0x1C, "fail");

_Static_assert(offsetof(struct siginfo64, si_addr) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo32, si_addr) == 0x0C, "fail");
_Static_assert(offsetof(struct siginfo64, si_addr_lsb) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo32, si_addr_lsb) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo64, si_lower) == 0x20, "fail");
_Static_assert(offsetof(struct siginfo64, si_upper) == 0x28, "fail");
_Static_assert(offsetof(struct siginfo32, si_lower) == 0x14, "fail");
_Static_assert(offsetof(struct siginfo32, si_upper) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo64, si_pkey) == 0x20, "fail");
_Static_assert(offsetof(struct siginfo32, si_pkey) == 0x14, "fail");

_Static_assert(offsetof(struct siginfo64, si_band) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo64, si_fd) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo32, si_band) == 0x0C, "fail");
_Static_assert(offsetof(struct siginfo32, si_fd) == 0x10, "fail");

_Static_assert(offsetof(struct siginfo64, si_call_addr) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo64, si_syscall) == 0x18, "fail");
_Static_assert(offsetof(struct siginfo64, si_arch) == 0x1c, "fail");
_Static_assert(offsetof(struct siginfo32, si_call_addr) == 0x0C, "fail");
_Static_assert(offsetof(struct siginfo32, si_fd) == 0x10, "fail");
_Static_assert(offsetof(struct siginfo32, si_arch) == 0x14, "fail");

enum {
	NT_PRSTATUS = 1,
	NT_PRFPREG = 2,
	NT_PRXFPREG = 0x46e62b7f,
	NT_386_TLS = 0x200,
	NT_386_IOPERM = 0x201,
	NT_X86_XSTATE = 0x202,
};

enum {
	REG32_EBX = 0x00,
	REG32_ECX = 0x04,
	REG32_EDX = 0x08,
	REG32_ESI = 0x0c,
	REG32_EDI = 0x10,
	REG32_EBP = 0x14,
	REG32_EAX = 0x18,
	REG32_DS = 0x1c,
	REG32_ES = 0x20,
	REG32_FS = 0x24,
	REG32_GS = 0x28,
	REG32_ORIG_EAX = 0x2c,
	REG32_EIP = 0x30,
	REG32_CS = 0x34,
	REG32_EFLAGS = 0x38,
	REG32_ESP = 0x3c,
	REG32_SS = 0x40,
};

enum {
	REG64_R15 = 0x00,
	REG64_R14 = 0x08,
	REG64_R13 = 0x10,
	REG64_R12 = 0x18,
	REG64_RBP = 0x20,
	REG64_RBX = 0x28,
	REG64_R11 = 0x30,
	REG64_R10 = 0x38,
	REG64_R9 = 0x40,
	REG64_R8 = 0x48,
	REG64_RAX = 0x50,
	REG64_RCX = 0x58,
	REG64_RDX = 0x60,
	REG64_RSI = 0x68,
	REG64_RDI = 0x70,
	REG64_ORIG_RAX = 0x78,
	REG64_RIP = 0x80,
	REG64_CS = 0x88,
	REG64_RFLAGS = 0x90,
	REG64_RSP = 0x98,
	REG64_SS = 0xa0,
	REG64_FS_BASE = 0xa8,
	REG64_GS_BASE = 0xb0,
	REG64_DS = 0xb8,
	REG64_ES = 0xc0,
	REG64_FS = 0xc8,
	REG64_GS = 0xd0,
};

static int (*bpf_copy_from_user)(void *dst, size_t size, uint64_t user_ptr) = (void *) 148;
static int (*bpf_copy_to_user)(uint64_t user_ptr, const void *ptr, size_t size) = (void *) 165;
static int (*bpf_getregset)(uint32_t type, uint64_t offset, void *ptr, size_t size) = (void *) 163;
static int (*bpf_setregset)(uint32_t type, uint64_t offset, const void *ptr, size_t size) = (void *) 164;

#define memcpy __builtin_memcpy
#define memset __builtin_memset

#endif
