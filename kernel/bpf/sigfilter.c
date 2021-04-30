#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/regset.h>
#include <linux/bpf.h>


BPF_CALL_3(bpf_copy_to_user, void __user *, uptr, const void*, ptr, unsigned long, size) {
    int ret = copy_to_user(uptr, ptr, size);
    if (unlikely(ret)) {
        return -EFAULT;
    }
    return ret;
}

const struct bpf_func_proto bpf_copy_to_user_proto = {
	.func		= bpf_copy_to_user,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

static const struct user_regset *
find_regset(const struct user_regset_view *view, unsigned int type)
{
	const struct user_regset *regset;
	int n;

	for (n = 0; n < view->n; ++n) {
		regset = view->regsets + n;
		if (regset->core_note_type == type)
			return regset;
	}

	return NULL;
}


BPF_CALL_4(bpf_getregset, unsigned, type, unsigned long, offset, void *, ptr, unsigned long, size) {
#warning enedil CHECK NO BUG
    const struct user_regset_view *view = task_user_regset_view(current);
   	const struct user_regset *regset = find_regset(view, type);

    void *data;
    int ret = regset_get_alloc(current, regset, offset + size, &data);
    if (ret)
        return ret;

    memcpy(ptr, data + offset, size);
    kfree(data);

    return ret;
}

const struct bpf_func_proto bpf_getregset_proto = {
	.func		= bpf_getregset,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_4(bpf_setregset, unsigned, type, unsigned long, offset, const void *, ptr, unsigned long, size) {
#warning enedil IMPLEMENT ME
    return -EINVAL;
}

const struct bpf_func_proto bpf_setregset_proto = {
	.func		= bpf_setregset,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
};

const struct bpf_func_proto *
sigfilter_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog) {
    switch (func_id) {
    case BPF_FUNC_getregset:
        return &bpf_getregset_proto;
    case BPF_FUNC_setregset:
        return &bpf_setregset_proto;
    case BPF_FUNC_copy_to_user:
        return &bpf_copy_to_user_proto;
    case BPF_FUNC_copy_from_user:
        return &bpf_copy_from_user_proto;
    default:
        return bpf_base_func_proto(func_id);
    }
}

static bool sigfilter_valid_access_32(int off, int size) {
    if (off >= sizeof(struct compat_siginfo))
        return false;
    switch (off) {
    case bpf_ctx_range(struct compat_siginfo, si_code):
    case bpf_ctx_range(struct compat_siginfo, si_errno):
    case bpf_ctx_range(struct compat_siginfo, si_signo):
    case bpf_ctx_range(struct compat_siginfo, _sifields):
        break;
    default:
        return false;
    }
#warning ctx_wide_access_ok itd
    return true;
}

static bool sigfilter_valid_access_64(int off, int size) {
    if (off >= sizeof(kernel_siginfo_t))
        return false;
    switch (off) {
    case bpf_ctx_range(kernel_siginfo_t, si_code):
    case bpf_ctx_range(kernel_siginfo_t, si_errno):
    case bpf_ctx_range(kernel_siginfo_t, si_signo):
    case bpf_ctx_range(kernel_siginfo_t, _sifields):
        break;
    default:
        return false;
    }
#warning ctx_wide_access_ok itd
    return true;
}

static bool sigfilter_valid_access(int off, int size, enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info) {
    bool (*fun)(int, int) = in_compat_syscall() ? sigfilter_valid_access_32 : sigfilter_valid_access_64;
#warning valid_access -> shall I check expected_attach_type?
    /* XXX
    if (prog->expected_attach_type != BPF_SIGFILTER)
        return false;
    */
    if (off < 0)
        return false;
    if (off % size != 0)
        return false;
    return fun(off, size);
}


static u32 bpf_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *src,
				  struct bpf_insn *dst,
				  struct bpf_prog *prog, u32 *target_size) {
    return 42;
}
/*
struct bpf_verifier_ops {
	/x* return eBPF function prototype for verification *x/
	const struct bpf_func_proto *
	(*get_func_proto)(enum bpf_func_id func_id,
			  const struct bpf_prog *prog);

	/x* return true if 'size' wide access at offset 'off' within bpf_context
	 * with 'type' (read or write) is allowed
	 *x/
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info);
	int (*gen_prologue)(struct bpf_insn *insn, bool direct_write,
			    const struct bpf_prog *prog);
	int (*gen_ld_abs)(const struct bpf_insn *orig,
			  struct bpf_insn *insn_buf);
	u32 (*convert_ctx_access)(enum bpf_access_type type,
				  const struct bpf_insn *src,
				  struct bpf_insn *dst,
				  struct bpf_prog *prog, u32 *target_size);
	int (*btf_struct_access)(struct bpf_verifier_log *log,
				 const struct btf *btf,
				 const struct btf_type *t, int off, int size,
				 enum bpf_access_type atype,
				 u32 *next_btf_id);
};
*/

static int bpf_prog_test_run_sigfilter(struct bpf_prog *prog, const union bpf_attr *kattr, union bpf_attr __user *uattr) {
#warning test run sigfilter
    // XXX
    printk("NDSJOKAFDSAO");
    return 3;
}


const struct bpf_verifier_ops sigfilter_verifier_ops = {
	.get_func_proto		= sigfilter_func_proto,
	.is_valid_access	= sigfilter_valid_access,
	.convert_ctx_access	= bpf_convert_ctx_access,
};

const struct bpf_prog_ops sigfilter_prog_ops = {
	.test_run		= bpf_prog_test_run_sigfilter,
};


// Copied from kernel/ptrace.c
static int sigfilter_getsiginfo(struct task_struct *child, kernel_siginfo_t *info)
{
	unsigned long flags;
	int error = -ESRCH;

	if (lock_task_sighand(child, &flags)) {
		error = -EINVAL;
		if (likely(child->last_siginfo != NULL)) {
			copy_siginfo(info, child->last_siginfo);
			error = 0;
		}
		unlock_task_sighand(child, &flags);
	}
	return error;
}

// Copied from kernel/ptrace.c
static int sigfilter_setsiginfo(struct task_struct *child, const kernel_siginfo_t *info)
{
	unsigned long flags;
	int error = -ESRCH;

	if (lock_task_sighand(child, &flags)) {
		error = -EINVAL;
		if (likely(child->last_siginfo != NULL)) {
			copy_siginfo(child->last_siginfo, info);
			error = 0;
		}
		unlock_task_sighand(child, &flags);
	}
	return error;
}
