#pragma once
#include <linux/bpf.h>

static inline bool bpf_sigfilter_is_sleepable(u32 btf_id) {
#warning This is prolly more complicated.
    return true;
}
