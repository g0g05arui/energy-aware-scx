// SPDX-License-Identifier: GPL-2.0
/* Simple FIFO sched_ext scheduler */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* 
 * Simple FIFO scheduler - just dispatch tasks to the local DSQ in order.
 * This is the simplest possible scheduler: first-in, first-out on each CPU.
 */

/*
 * Called when a task is waking up. Dispatch it to the local CPU's DSQ.
 */
void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Simply dispatch to the local DSQ - tasks run in FIFO order */
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
}

/*
 * Called when the CPU is looking for the next task to run.
 * With local DSQ, this is handled automatically.
 */
void BPF_STRUCT_OPS(fifo_dispatch, s32 cpu, struct task_struct *prev)
{
	/* Move tasks from local DSQ to the CPU - BPF handles FIFO ordering */
	scx_bpf_dsq_move_to_local(SCX_DSQ_LOCAL);
}

/*
 * Called when a task is being scheduled.
 */
void BPF_STRUCT_OPS(fifo_running, struct task_struct *p)
{
	/* Nothing special to do */
}

/*
 * Called when a task stops running.
 */
void BPF_STRUCT_OPS(fifo_stopping, struct task_struct *p, bool runnable)
{
	/* Nothing to do - task will be re-enqueued if still runnable */
}

/*
 * Initialize the scheduler.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init)
{
	return scx_bpf_create_dsq(0, -1);
}

/*
 * Cleanup when scheduler is being unloaded.
 */
void BPF_STRUCT_OPS(fifo_exit, struct scx_exit_info *ei)
{
	/* Nothing to cleanup */
}

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
