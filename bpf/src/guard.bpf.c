#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define EPERM 1

/* we are going to populate this map with new processes */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u8);
} tracked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} guard_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
	__u32 pid;
	__u32 ppid;
	__u8 command[TASK_COMM_LEN];
	__u8 path[MAX_PATH_LEN];
	__u8 denied;
};

/* https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/include/trace/events/sched.h#L396 
 * use tp_btf tracepoints, so we have BTF and task_struct at the same time */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(execguard_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	__u32 child_pid = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);
	__u8 val = 1;

	/* new thread */
	if (child_pid != child_tgid) {
		return 0;
	}

	/* parent is not in out map, no need to move on */
	__u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &parent_tgid);
	if (!tracked) {
		return 0;
	}

	bpf_map_update_elem(&tracked_pids, &child_tgid, &val, BPF_ANY);

	return 0;
}

/* https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/include/trace/events/sched.h#L335 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(execguard_exit, struct task_struct *task)
{
	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);

	/* just a thread */
	if (pid != tgid) {
		return 0;
	}

	/* delete complete process from map */
	bpf_map_delete_elem(&tracked_pids, &tgid);

	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(execguard_sec, struct linux_binprm *bprm, int ret)
{
	if (ret < 0) {
		return ret;
	}

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	__u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &tgid);
	if (!tracked) {
		return 0;
	}

	__u32 config_key = 0;
	__u8 *enforce = bpf_map_lookup_elem(&guard_config, &config_key);
	__u8 enforcing = enforce ? *enforce : 0;

	/* submit event to ring buffer */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (e) {
		struct task_struct *t = bpf_get_current_task_btf();

		e->pid = tgid;
		e->ppid = BPF_CORE_READ(t, real_parent, tgid);
		e->denied = enforcing;

		bpf_get_current_comm(&e->command, TASK_COMM_LEN);
		bpf_probe_read_kernel_str(&e->path, MAX_PATH_LEN,
					  bprm->filename);

		bpf_ringbuf_submit(e, 0);
	}

	if (enforcing) {
		return -EPERM;
	}

	return 0;
}
