/* Simple FIFO sched_ext scheduler */
#include "vmlinux.h"
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(fifo_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SCX_DSQ_LOCAL);
}

void BPF_STRUCT_OPS(fifo_running, struct task_struct *p){}

void BPF_STRUCT_OPS(fifo_stopping, struct task_struct *p, bool runnable){}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init)
{
	return scx_bpf_create_dsq(0, -1);
}

void BPF_STRUCT_OPS(fifo_exit, struct scx_exit_info *ei){}

SEC(".struct_ops.link")
struct sched_ext_ops fifo_ops = {
	.enqueue		= (void *)fifo_enqueue,
	.dispatch		= (void *)fifo_dispatch,
	.running		= (void *)fifo_running,
	.stopping		= (void *)fifo_stopping,
	.init			= (void *)fifo_init,
	.exit			= (void *)fifo_exit,
	.name			= "fifo",
};
