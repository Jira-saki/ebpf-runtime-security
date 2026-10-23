// tracer.bpf.c
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// โครงสร้าง event ที่จะส่งกลับมาให้ฝั่ง Go (Userspace)
struct event {
    __u32 pid;
    char comm[16];
    char filename[256];
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
    // สำหรับ sys_enter_openat parameter ตัวที่สองคือ const char *filename (offset 24 หรือ 16 byte)
    const char **filename_ptr = (const char **)(ctx + 24);
    const char *filename = *filename_ptr;
    
    // อ่าน string จาก Userspace เข้าสู่ Kernel Buffer อย่างปลอดภัย
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // ปล่อยข้อมูลขึ้น Ring Buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}
