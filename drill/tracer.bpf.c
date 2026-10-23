//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    char comm[16];
    char filename[256];
    __u32 event_type; // 1 = openat, 2 = execve
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->event_type = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char **filename_ptr = (const char **)(ctx + 24);
    const char *filename = *filename_ptr;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->event_type = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char **filename_ptr = (const char **)(ctx + 16);
    const char *filename = *filename_ptr;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
