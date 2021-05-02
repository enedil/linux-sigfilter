#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/regset.h>
#include <linux/bpf.h>


BPF_CALL_3(bpf_copy_to_user, void __user *, uptr, const void*, ptr, unsigned long, size) {
    int ret;
    // printk("copy_to_user size=%lu\n", size);
    ret = copy_to_user(uptr, ptr, size);
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

static const struct user_regset *get_regset(unsigned type) {
    const struct user_regset_view *view = task_user_regset_view(current);
   	return find_regset(view, type);
}

BPF_CALL_4(bpf_getregset, unsigned, type, unsigned long, offset, void *, ptr, unsigned long, size) {
    int ret;
    void *data;
   	const struct user_regset *regset = get_regset(type);
    if (regset == NULL)
        return -EINVAL;

    if (size + offset < offset)
        return -EINVAL;
    if (offset % regset->size != 0)
        return -EINVAL;
    if (size % regset->size != 0)
        return -EINVAL;

    ret = regset_get_alloc(current, regset, offset + size, &data);
    //printk("get regset (%d) regset=%p offset=%lu size=%lu offset+size=%lu\n", ret, regset, offset, size, offset+size);
    if (ret < 0 || ret != offset + size)
        return ret;

    memcpy(ptr, data + offset, size);
    kfree(data);

    return 0;
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
    int ret;
   	const struct user_regset *regset = get_regset(type);
    if (regset == NULL)
        return -EINVAL;
    if (size + offset < offset)
        return -EINVAL;
    if (offset % regset->size != 0)
        return -EINVAL;
    if (size % regset->size != 0)
        return -EINVAL;

    // printk("set regset regset=%p offset=%lu size=%lu ptr=%p\n", regset, offset, size, ptr);
    ret = regset->set(current, regset, offset, size, ptr, NULL);
    return ret;
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
    if (type == BPF_WRITE)
        return false;
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

const struct bpf_verifier_ops sigfilter_verifier_ops = {
	.get_func_proto		= sigfilter_func_proto,
	.is_valid_access	= sigfilter_valid_access,
};

const struct bpf_prog_ops sigfilter_prog_ops = {};
