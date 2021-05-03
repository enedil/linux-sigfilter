#pragma once
#include <linux/bpf.h>


void __unset_sigfilter(struct task_struct *t);
//void __unset_sigfilter_nolock(struct task_struct *t);
