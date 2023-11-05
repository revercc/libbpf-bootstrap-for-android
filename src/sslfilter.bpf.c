#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "sslfilter.h"

// BPF_MAP_TYPE_ARRAY类型map是数组类型
// max_entries相当于数组长度（元素个数）
// key是数组索引（8个字节）
// value是数组元素
// 因为数组map创建后，相当于所有的key(索引)都是默认存在的，和hash map类型不一样
struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct SSL_FILTER_INFO);
} ssl_filter_info SEC(".maps");

struct READ_ENTRY_ARGS{
    u64 buf_address;
    u64 readbytes_address;
    u64 stack_id;
};

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u64);
    __type(value, struct READ_ENTRY_ARGS);
}read_entry_args SEC(".maps");

// BPF_MAP_TYPE_PERF_EVENT_ARRAY类型map的max_entries等与cpu数量
// value是perfbuf map的文件句柄
struct{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));    
} events SEC(".maps");

// BPF_MAP_TYPE_STACK_TRACE类型map 用来保存栈调用链信息
// key 就是bpf_get_stackid生成的栈信息hash值
// value 就是对应的栈调用链，设置大小就是设置最大获取的栈调用深度
struct{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 0x10 * sizeof(u64));
    __uint(max_entries, 1000);
}stack_map SEC(".maps");

//int ssl_write_internal(SSL *s, const void *buf, size_t num, size_t *written)
SEC("uprobe")
int BPF_KPROBE(ssl_write_internal_entry, void *SSL, void *buf, size_t num, size_t *written)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u64 index = 0;
    struct SSL_FILTER_INFO *p_filter_info = bpf_map_lookup_elem(&ssl_filter_info, &index);
    if(p_filter_info == NULL){
        return 0;
    }
    
    p_filter_info->bWrite = true;
    p_filter_info->pid = pid;
    p_filter_info->size = num;
    bpf_get_current_comm(&p_filter_info->comm, sizeof(p_filter_info->comm));
    if(bpf_probe_read_user(&p_filter_info->buf, num < sizeof(p_filter_info->buf) ? num : sizeof(p_filter_info->buf), buf) < 0){
        return 0;
    }

    // get starck function call list and get stack_id
    p_filter_info->stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
        p_filter_info, sizeof(*p_filter_info));

    return 0;
}

//int ssl_read_internal(SSL *s, void *buf, size_t num, size_t *readbytes)
SEC("uprobe")
int BPF_KPROBE(ssl_read_internal_entry, void *SSL, void *buf, size_t num, size_t *readbytes)
{
    struct READ_ENTRY_ARGS args = {};
    args.readbytes_address = (u64)readbytes;
    args.buf_address = (u64)buf;
     // get starck function call list and get stack_id
    args.stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&read_entry_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(ssl_read_internal_exit, int ret)
{
    if(ret == -1){
        return 0;
    }

    u64 index = 0;
    struct SSL_FILTER_INFO *p_filter_info = bpf_map_lookup_elem(&ssl_filter_info, &index);
    if(p_filter_info == NULL){
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    struct READ_ENTRY_ARGS *p_args = bpf_map_lookup_elem(&read_entry_args, &pid_tgid);
    if(p_args == NULL){
        return 0;
    }

    size_t readbytes;
    if(bpf_probe_read_user(&readbytes, sizeof(readbytes), (size_t*)p_args->readbytes_address) < 0){
        return 0;
    }

    p_filter_info->pid = pid;
    p_filter_info->size = readbytes;
    p_filter_info->bWrite = false;
    p_filter_info->stack_id = p_args->stack_id;
    bpf_get_current_comm(&p_filter_info->comm, sizeof(p_filter_info->comm));
    if(bpf_probe_read_user(&p_filter_info->buf, 
        readbytes < sizeof(p_filter_info->buf) ? readbytes : sizeof(p_filter_info->buf), 
        (void*)p_args->buf_address) < 0){
        return 0;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
        p_filter_info, sizeof(*p_filter_info));
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
