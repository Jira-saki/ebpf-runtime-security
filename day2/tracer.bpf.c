// tracer.bpf.c
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// โครงสร้าง event เดิมสำหรับ openat
struct event {
    __u32 pid;
    char comm[16];
    char filename[256];
};

// โครงสร้าง event ที่จะส่งกลับมาให้ฝั่ง Go (Userspace) สำหรับ connect
struct connect_event {
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 pad;      // เติม padding 2 bytes ให้ครบ 4 bytes ชัดเจน
    char comm[16];
};

struct trace_event_raw_sys_enter_connect {
    __u64 unused;
    long int id;
    long unsigned int fd;
    struct sockaddr *uservaddr; // offset 24
    long unsigned int addrlen;
};

// Map ชนิด Ring Buffer เพื่อส่งข้อมูลประสิทธิภาพสูงกลับขึ้น Userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Hook เข้า Tracepoint: syscalls/sys_enter_openat
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
    struct event *e;
    
    // จอง memory บน Ring Buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // ดึง Process ID และ Thread ID
    e->pid = bpf_get_current_pid_tgid() >> 32;

    // ดึงชื่อ Process (Command Name)
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // อ่าน pointer ของ filename จากโครงสร้าง tracepoint
    const char **filename_ptr = (const char **)(ctx + 24);
    const char *filename = *filename_ptr;
    
    // อ่าน string จาก Userspace เข้าสู่ Kernel Buffer อย่างปลอดภัย
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // ปล่อยข้อมูลขึ้น Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook เข้า Tracepoint: syscalls/sys_enter_connect
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter_connect *ctx) {
    struct sockaddr_in sa;
    struct connect_event *e;

    if (!ctx->uservaddr)
        return 0;

    // อ่าน Family ดูก่อนว่าเป็น IPv4 (AF_INET = 2) หรือไม่
    short family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr) < 0)
        return 0;

    if (family != 2) // AF_INET
        return 0;

    // อ่าน struct sockaddr_in จาก userspace memory
    if (bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr) < 0)
        return 0;

    // จอง buffer ส่งกลับ Userspace
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->daddr = sa.sin_addr.s_addr;
    e->dport = __builtin_bswap16(sa.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}