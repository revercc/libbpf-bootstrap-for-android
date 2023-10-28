// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf/bpf_tracing.h"
#include "opensnoop.h"

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile bool targ_failed = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}
	return true;
}

/*
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
*/
SEC("kprobe/__arm64_sys_open")
int BPF_KPROBE(__arm64_sys_open)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};

		struct pt_regs *regs = (struct pt_regs*)PT_REGS_PARM1(ctx);
		if(bpf_probe_read_kernel(&args.fname, sizeof(args.fname), regs) < 0){
			return 0;
		}
		if(bpf_probe_read_kernel(&args.flags, sizeof(args.flags), (char*)regs + sizeof(u64))){
			return 0;
		}
		char buf[5];
		if(bpf_probe_read_user_str(&buf, sizeof(buf), args.fname) < 0){
			bpf_printk("fname : %p", args.fname);
			return 0;
		}
		bpf_printk("fname is : %s ", buf);
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

/*
SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags,
		umode_t, mode)
*/
SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(__arm64_sys_openat)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	/* store arg info for later lookup */
	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};
		struct pt_regs *regs = (struct pt_regs*)PT_REGS_PARM1(ctx);
		if(bpf_probe_read_kernel(&args.fname, sizeof(args.fname), (char*)regs + sizeof(u64)) < 0){
			return 0;
		}
		if(bpf_probe_read_kernel(&args.flags, sizeof(args.flags), (char*)regs + sizeof(u64) * 2) < 0){
			return 0;
		}
		bpf_map_update_elem(&start, &pid, &args, 0);
	}
	return 0;
}

static __always_inline
int trace_exit(void* ctx, int ret)
{
	struct event event = {};
	struct args_t *ap;
	uintptr_t stack[3];
	u32 pid = bpf_get_current_pid_tgid();

	ap = bpf_map_lookup_elem(&start, &pid);
	if (!ap)
		return 0;	/* missed entry */
	if (targ_failed && ret >= 0)
		goto cleanup;	/* want failed only */

	/* event data */
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
	event.flags = ap->flags;
	event.ret = ret;

	bpf_get_stack(ctx, &stack, sizeof(stack),
		      BPF_F_USER_STACK);
	/* Skip the first address that is usually the syscall it-self */
	event.callers[0] = stack[1];
	event.callers[1] = stack[2];

	bpf_printk("event.fname is : %s", event.fname);
	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("kretprobe/__arm64_sys_open")
int BPF_KRETPROBE(__arm64_sys_open__exit)
{
	return trace_exit(ctx, (int)PT_REGS_RC(ctx));
}

SEC("kretprobe/__arm64_sys_openat")
int BPF_KRETPROBE(__arm64_sys_openat_exit)
{
	return trace_exit(ctx, (int)PT_REGS_RC(ctx));
}

char LICENSE[] SEC("license") = "GPL";
