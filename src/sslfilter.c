#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include "bpf/libbpf_legacy.h"
#include "sslfilter.h"
#include "sslfilter.skel.h"

// 为每个cpu分配8个缓存页用来存放perfbuffer
#define PERF_BUFFER_PAGES	64
// 获取响应的超时时间
#define PERF_POLL_TIMEOUT_MS	100

// 保存栈函数调用链
struct bpf_stacktrace {
    uint64_t ip[0x10];
};

static struct env {
	bool verbose;
    bool outhex;
    bool print_stack;
    bool frame_point;
    pid_t target_pid;
    char ssl_lib_path[PATH_MAX];
    size_t ssl_wirte_internal_offset;
    size_t ssl_read_internal_offset;
} env = {
    .outhex = false,
    .print_stack = false,
    .frame_point = false,
    .target_pid = 0xFFFFFFFF,
    .ssl_lib_path = {0},
    .ssl_wirte_internal_offset = 0xFFFFFFFF,
    .ssl_read_internal_offset = 0xFFFFFFFF
};

const char argp_program_doc[] =
"USAGE: opensnoop -p -s -w -r -h -s -f\n"
"\n"
"  -p    : pid\n"
"  -w    : ssl_write_internal_offset\n"
"  -r    : ssl_read_internal_offset\n"
"  -l    : ssl lib path\n"
"  -h    : output hex\n"
"  -s    : print stack\n"
"  -f    : print frame point\n"
"";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "trace process pid"},
	{ "writeOff", 'w', "WRITEOFF", 0, "ssl_write_internal function offset"},
	{ "readOff", 'r', "READOFF", 0, "ssl_read_internal function offset"},
    { "sslLibPath", 'l', "SSLPATH", 0, "ssl lib path"},
    { "outhex", 'h', NULL, 0, "output hex"},
    { "stack", 's', NULL, 0, "print stack"},
    { "framepoint", 'f', NULL, 0, "print frame point"},
	{},
};

struct sslfilter_bpf* skel;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    pid_t pid = 0;
    size_t write_offset = 0;
    size_t read_offset = 0;
    switch (key) {
    case 'p':
        errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.target_pid = pid;
		break;
    case 'w':
        errno = 0;
		write_offset = strtol(arg, NULL, 16);
		if (errno || write_offset <= 0) {
			fprintf(stderr, "Invalid write offset: %s\n", arg);
			argp_usage(state);
		}
		env.ssl_wirte_internal_offset = write_offset;
		break;
    case 'r':
        errno = 0;
		read_offset = strtol(arg, NULL, 16);
		if (errno || read_offset <= 0) {
			fprintf(stderr, "Invalid read offset: %s\n", arg);
			argp_usage(state);
		}
		env.ssl_read_internal_offset = read_offset;
		break;
    case 'l':
        errno = 0;
        strcpy(env.ssl_lib_path, arg);
        if(errno){
            fprintf(stderr, "Invalid ssl lib path: %s\n", arg);
			argp_usage(state);
        }
        break;
    case 'h':
        env.outhex = true;
        break;
    case 's':
        env.print_stack = true;
        break;
    case 'f':
        env.frame_point = true;
        break;
    default:
		return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')
void dump_hex(const uint8_t *buf, uint32_t size)
{
    int i, j;
    for (i = 0; i < size; i += 16){
        printf("%08X: ", i);
        for (j = 0; j < 16; j++){
            if (i + j < size) {
                printf("%02X ", buf[i + j]);
            }
            else {
                printf("   ");
            }
        }
        printf(" ");

        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}

// 打印perfbuffer中的数据
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct SSL_FILTER_INFO *ssl_filter_info = data;
    // print function call list
    if(env.frame_point == true){
        struct bpf_stacktrace stacktrace = {0};
        if (bpf_map_lookup_elem(
            bpf_map__fd(skel->maps.stack_map),
            &ssl_filter_info->stack_id,
            &stacktrace) == 0){
            printf("\nstack_id = %lld:\n", ssl_filter_info->stack_id);
            for(int i = 0; i < 0x10; i++){
                if(stacktrace.ip[i]){
                    printf("address : %p\n", (void*)stacktrace.ip[i]);
                } 
            }
        }
    }

    // printf data
    if(ssl_filter_info->bWrite){
        printf("\e[0;31m");
        printf("SSL_write-------------------------------------------------------\n");
        printf("%-10d %-32s %-10d\n", ssl_filter_info->pid, ssl_filter_info->comm, ssl_filter_info->size);
        if(env.outhex == true){
            dump_hex((uint8_t*)ssl_filter_info->buf, ssl_filter_info->size);
        }
        else{
            printf("%s\n", ssl_filter_info->buf);
        }
        printf("\e[0m" );
    }
    else{
        printf("\e[0;32m");
        printf("SSL_read--------------------------------------------------------\n");
        printf("%-10d %-32s %-10d\n", ssl_filter_info->pid, ssl_filter_info->comm, ssl_filter_info->size);
        if(env.outhex == true){
            dump_hex((uint8_t*)ssl_filter_info->buf, ssl_filter_info->size);
        }
        else{
            printf("%s\n", ssl_filter_info->buf);
        }
        printf("\e[0m" );
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[], char *envp[])
{
    int err;
    //struct sslfilter_bpf* skel;
    struct perf_buffer *perfbuf = NULL;
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);

    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err || !strlen(env.ssl_lib_path) ||
        env.target_pid == 0xffffffff ||
        env.ssl_wirte_internal_offset == 0xffffffff ||
        env.ssl_read_internal_offset == 0xffffffff){
        fprintf(stderr, "error args\n");
		return err;
    }

    // 设置错误和调试信息输出回调函数
    libbpf_set_print(libbpf_print_fn);

    // 打开 skeleton
    skel = sslfilter_bpf__open_opts(&open_opts);
    if(!skel){
        fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
    }

    // 将打开的skeleton中的bpf字节码加载到内核中并进行验证
    err = sslfilter_bpf__load(skel);
    if(err){
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
    }

    // 附加ssl_write_internal函数到uprobe
    skel->links.ssl_write_internal_entry = bpf_program__attach_uprobe(
        skel->progs.ssl_write_internal_entry,
        false, 
        env.target_pid,
        env.ssl_lib_path, 
        env.ssl_wirte_internal_offset);
    err = libbpf_get_error(skel->links.ssl_write_internal_entry);
    if(err){
        fprintf(stderr, "attach ssl_write uprobe error\n");
        goto cleanup;
    }

    // 附加ssl_read_internal函数到uprobe
    skel->links.ssl_read_internal_entry = bpf_program__attach_uprobe(
        skel->progs.ssl_read_internal_entry,
        false,
        env.target_pid,
        env.ssl_lib_path,
        env.ssl_read_internal_offset);
    err = libbpf_get_error(skel->links.ssl_read_internal_entry);
    if(err){
        fprintf(stderr, "attach ssl_read uprobe error\n");
        goto cleanup;
    }

    //附加ssl_read_internal_exit函数到uretprobe
    skel->links.ssl_read_internal_exit = bpf_program__attach_uprobe(
        skel->progs.ssl_read_internal_exit,
        true,
        env.target_pid,
        env.ssl_lib_path,
        env.ssl_read_internal_offset);
    err = libbpf_get_error(skel->links.ssl_read_internal_exit);
    if(err){
        fprintf(stderr, "attach ssl_read uretprobe error\n");
        goto cleanup;
    }

    // 是否打印堆栈
	struct perf_buffer_opts perf_opts = {};
    perf_opts.sz = sizeof(perf_opts);
    if(env.print_stack == true){
        perf_opts.unwind_call_stack = 1;
    }
    
    // bpf_map__fd获取perf event map的文件句柄
    // perf_buffer__new调用perf_open_event
    perfbuf = perf_buffer__new(
        bpf_map__fd(skel->maps.events), 
        PERF_BUFFER_PAGES,
		handle_event, 
        handle_lost_events, 
        NULL,
        &perf_opts);

	if (!perfbuf) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

    // 支持ctry-C结束进程
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

    // 轮询读取perfbuffer
	while (!exiting) {
		err = perf_buffer__poll(perfbuf, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
    // 释放perfbuffer
    perf_buffer__free(perfbuf);
    // 释放资源
    sslfilter_bpf__destroy(skel);
	return err != 0;
}