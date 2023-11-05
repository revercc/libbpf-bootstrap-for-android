#ifndef __SSLFILTER_H
#define __SSLFILTER_H

#define MAX_SSL_PACKAGE_SIZE 16384
struct SSL_FILTER_INFO{
    __u32 pid;
    __u64 time;
    __u32 size;
    __u64 stack_id;
    bool bWrite;
    char comm[16];
    char buf[MAX_SSL_PACKAGE_SIZE];
};

#endif