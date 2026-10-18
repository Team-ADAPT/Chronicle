#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chronicle - eBPF telemetry collector for building the training dataset
======================================================================

"The Operating System observes, the DBMS remembers, ML detects."
This script is the *observe* part. It runs on a Linux host, attaches eBPF
programs (via BCC) and, together with psutil, writes a labelled dataset that
mirrors the Chronicle PostgreSQL schema (process_instances, telemetry_events,
behaviour_windows) plus system-wide resource metrics and per-window syscall
histograms (needed for ADFA-LD / LID-DS style syscall features).

What is collected
-----------------
eBPF (kernel):
  * process exec / fork / exit  + parent->child relationships
  * every syscall, counted per (process, syscall) in-kernel (cheap, lossless)
    and optionally a raw syscall sequence (--trace-syscalls)
  * file events: open/openat/creat (read/write/create/truncate intent),
    unlink/unlinkat, rename/renameat/renameat2
  * bytes read()/written() per process
  * network: TCP connect (v4/v6), TCP accept, TCP tx/rx bytes, UDP tx bytes
psutil (user space, every window):
  * per process: CPU %, RSS/VMS, threads, open fds, disk read/write bytes,
    context switches
  * system wide: CPU (user/system/iowait/idle), load, RAM, swap, disk usage,
    disk I/O, network I/O, connection counts, process count

Output (one folder per run):  <out>/<experiment_id>/
  metadata.json            reproducibility record (kernel, hw, versions, args)
  process_instances.csv    one row per process instance (+ parent link)
  telemetry_events.csv     raw semantic events (exec/fork/exit/file/net)
  behaviour_windows.csv    per-process, per-window feature rows  (+ label)
  syscall_histogram.csv    per-process, per-window syscall counts (long format)
  system_metrics.csv       system-wide CPU/RAM/disk/network per window (+ label)
  syscall_trace.csv        (only with --trace-syscalls) raw syscall sequence

Usage (as root):
  sudo python3 chronicle_collector.py --label benign --scenario idle_desktop --duration 600
  sudo python3 chronicle_collector.py --label malicious --scenario ransomware_sim --duration 300

Requirements: Linux >= 5.5 (4.x mostly works), root, BCC + kernel headers, psutil.
  sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r) python3-psutil
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import os
import platform
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

try:
    import psutil
except ImportError:  # pragma: no cover
    sys.exit("psutil is required:  sudo apt install python3-psutil   (or pip install psutil)")

# --------------------------------------------------------------------------- #
# eBPF program (BCC flavour of C).  Optional probes are guarded by -DHAVE_xxx,
# which the Python side sets only if the tracepoint exists on this kernel.
# --------------------------------------------------------------------------- #
BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

#ifndef SELF_TGID
#define SELF_TGID 0
#endif

#define FNAME_LEN  256
#define FNAME2_LEN 128

enum ev_type {
    EV_EXEC = 1, EV_FORK, EV_EXIT, EV_OPEN, EV_UNLINK,
    EV_RENAME, EV_CONNECT, EV_ACCEPT, EV_SYSCALL
};

struct event_t {
    u64 ts;
    u32 pid;      /* tgid (process id)            */
    u32 tid;
    u32 ppid;     /* parent tgid (exec/fork)      */
    u32 uid;
    u32 type;
    u32 flags;    /* open flags / clone flags / exit code / unlink flags */
    s32 nr;       /* syscall number (EV_SYSCALL)  */
    u16 family;   /* AF_INET=2, AF_INET6=10       */
    u16 dport;
    u16 lport;
    u16 pad;
    u32 daddr4;
    u8  daddr6[16];
    char comm[16];
    char fname[FNAME_LEN];
    char fname2[FNAME2_LEN];   /* rename target */
};

#define EV_NOFILE_SZ ((u32)__builtin_offsetof(struct event_t, fname))
#define EV_FILE_SZ   ((u32)__builtin_offsetof(struct event_t, fname2))

struct sc_key_t   { u32 pid; u32 nr; };
struct pid_stats_t { u64 rd_bytes; u64 wr_bytes; u64 tcp_tx; u64 tcp_rx; u64 udp_tx; };

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);
BPF_HASH(sc_counts, struct sc_key_t, u64, 131072);
BPF_HASH(pid_stats, u32, struct pid_stats_t, 32768);
BPF_HASH(clone_flags, u32, u64, 8192);
BPF_HASH(currsock, u32, struct sock *);

static __always_inline struct event_t *new_event(u32 type)
{
    int z = 0;
    struct event_t *ev = scratch.lookup(&z);
    if (!ev) return 0;
    u64 pt = bpf_get_current_pid_tgid();
    u32 tgid = pt >> 32;
    if (tgid == 0 || tgid == SELF_TGID) return 0;
    ev->ts = bpf_ktime_get_ns();
    ev->pid = tgid;
    ev->tid = (u32)pt;
    ev->ppid = 0;
    ev->uid = (u32)bpf_get_current_uid_gid();
    ev->type = type;
    ev->flags = 0;
    ev->nr = 0;
    ev->family = 0;
    ev->dport = 0;
    ev->lport = 0;
    ev->pad = 0;
    ev->daddr4 = 0;
    __builtin_memset(ev->daddr6, 0, sizeof(ev->daddr6));
    ev->fname[0] = 0;
    ev->fname2[0] = 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    return ev;
}

static __always_inline struct pid_stats_t *stats_for(u32 pid)
{
    struct pid_stats_t zero = {};
    return pid_stats.lookup_or_try_init(&pid, &zero);
}

/* ---------------------------- process lifecycle --------------------------- */
TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct event_t *ev = new_event(EV_EXEC);
    if (!ev) return 0;
    unsigned off = args->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(ev->fname, sizeof(ev->fname), (char *)args + off);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->ppid = task->real_parent->tgid;
    events.perf_submit(args, ev, EV_FILE_SZ);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork)
{
    struct event_t *ev = new_event(EV_FORK);
    if (!ev) return 0;
    u64 pt = bpf_get_current_pid_tgid();
    u32 ctid = (u32)pt;
    ev->ppid = pt >> 32;                 /* creator (parent) tgid */
    ev->pid  = args->child_pid;          /* new task id           */
    ev->tid  = args->child_pid;
    __builtin_memcpy(ev->comm, args->child_comm, sizeof(ev->comm));
    u64 *fl = clone_flags.lookup(&ctid);
    if (fl) { ev->flags = (u32)*fl; clone_flags.delete(&ctid); }
    events.perf_submit(args, ev, EV_NOFILE_SZ);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u64 pt = bpf_get_current_pid_tgid();
    if ((pt >> 32) != (u32)pt) return 0;   /* ignore non-leader thread exits */
    struct event_t *ev = new_event(EV_EXIT);
    if (!ev) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->flags = task->exit_code >> 8;
    events.perf_submit(args, ev, EV_NOFILE_SZ);
    return 0;
}

#ifdef HAVE_CLONE
TRACEPOINT_PROBE(syscalls, sys_enter_clone)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 f = args->clone_flags;
    clone_flags.update(&tid, &f);
    return 0;
}
#endif
#ifdef HAVE_CLONE3
TRACEPOINT_PROBE(syscalls, sys_enter_clone3)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 f = 0;
    bpf_probe_read_user(&f, sizeof(f), (void *)args->uargs);   /* clone_args.flags is first */
    clone_flags.update(&tid, &f);
    return 0;
}
#endif

/* ------------------------------- syscalls --------------------------------- */
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || pid == SELF_TGID || args->id < 0) return 0;
    struct sc_key_t k = {};
    k.pid = pid;
    k.nr  = (u32)args->id;
    u64 zero = 0;
    u64 *c = sc_counts.lookup_or_try_init(&k, &zero);
    if (c) __sync_fetch_and_add(c, 1);
#ifdef TRACE_SEQ
    struct event_t *ev = new_event(EV_SYSCALL);
    if (ev) {
        ev->nr = (s32)args->id;
        events.perf_submit(args, ev, EV_NOFILE_SZ);
    }
#endif
    return 0;
}

/* ------------------------------ file events ------------------------------- */
static __always_inline int emit_open(void *ctx, const char *fname, u32 flags)
{
    struct event_t *ev = new_event(EV_OPEN);
    if (!ev) return 0;
    ev->flags = flags;
    bpf_probe_read_user_str(ev->fname, sizeof(ev->fname), fname);
    events.perf_submit(ctx, ev, EV_FILE_SZ);
    return 0;
}
static __always_inline int emit_unlink(void *ctx, const char *fname, u32 flags)
{
    struct event_t *ev = new_event(EV_UNLINK);
    if (!ev) return 0;
    ev->flags = flags;
    bpf_probe_read_user_str(ev->fname, sizeof(ev->fname), fname);
    events.perf_submit(ctx, ev, EV_FILE_SZ);
    return 0;
}
static __always_inline int emit_rename(void *ctx, const char *o, const char *n)
{
    struct event_t *ev = new_event(EV_RENAME);
    if (!ev) return 0;
    bpf_probe_read_user_str(ev->fname,  sizeof(ev->fname),  o);
    bpf_probe_read_user_str(ev->fname2, sizeof(ev->fname2), n);
    events.perf_submit(ctx, ev, sizeof(struct event_t));
    return 0;
}

#ifdef HAVE_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_open)     { return emit_open(args, args->filename, args->flags); }
#endif
#ifdef HAVE_OPENAT
TRACEPOINT_PROBE(syscalls, sys_enter_openat)   { return emit_open(args, args->filename, args->flags); }
#endif
#ifdef HAVE_CREAT
TRACEPOINT_PROBE(syscalls, sys_enter_creat)    { return emit_open(args, args->pathname, 0x241); } /* O_CREAT|O_WRONLY|O_TRUNC */
#endif
#ifdef HAVE_UNLINK
TRACEPOINT_PROBE(syscalls, sys_enter_unlink)   { return emit_unlink(args, args->pathname, 0); }
#endif
#ifdef HAVE_UNLINKAT
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) { return emit_unlink(args, args->pathname, args->flag); }
#endif
#ifdef HAVE_RENAME
TRACEPOINT_PROBE(syscalls, sys_enter_rename)   { return emit_rename(args, args->oldname, args->newname); }
#endif
#ifdef HAVE_RENAMEAT
TRACEPOINT_PROBE(syscalls, sys_enter_renameat)  { return emit_rename(args, args->oldname, args->newname); }
#endif
#ifdef HAVE_RENAMEAT2
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) { return emit_rename(args, args->oldname, args->newname); }
#endif

/* bytes actually read / written (files, pipes, sockets - everything via read/write) */
#ifdef HAVE_EXIT_READ
TRACEPOINT_PROBE(syscalls, sys_exit_read)
{
    if (args->ret <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || pid == SELF_TGID) return 0;
    struct pid_stats_t *s = stats_for(pid);
    if (s) __sync_fetch_and_add(&s->rd_bytes, (u64)args->ret);
    return 0;
}
#endif
#ifdef HAVE_EXIT_WRITE
TRACEPOINT_PROBE(syscalls, sys_exit_write)
{
    if (args->ret <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || pid == SELF_TGID) return 0;
    struct pid_stats_t *s = stats_for(pid);
    if (s) __sync_fetch_and_add(&s->wr_bytes, (u64)args->ret);
    return 0;
}
#endif

/* ------------------------------ network (kprobes) ------------------------- */
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    currsock.update(&tid, &sk);
    return 0;
}

static __always_inline int connect_return(struct pt_regs *ctx, int ipver)
{
    int ret = PT_REGS_RC(ctx);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&tid);
    if (!skpp) return 0;
    struct sock *skp = *skpp;
    currsock.delete(&tid);
    if (ret != 0) return 0;
    struct event_t *ev = new_event(EV_CONNECT);
    if (!ev) return 0;
    ev->dport = ntohs(skp->__sk_common.skc_dport);
    ev->lport = skp->__sk_common.skc_num;
    if (ipver == 4) {
        ev->family = 2;
        ev->daddr4 = skp->__sk_common.skc_daddr;
    } else {
        ev->family = 10;
        bpf_probe_read_kernel(&ev->daddr6, sizeof(ev->daddr6),
                              &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    events.perf_submit(ctx, ev, EV_NOFILE_SZ);
    return 0;
}
int trace_connect_v4_return(struct pt_regs *ctx) { return connect_return(ctx, 4); }
int trace_connect_v6_return(struct pt_regs *ctx) { return connect_return(ctx, 6); }

int trace_accept_return(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL) return 0;
    u16 family = newsk->__sk_common.skc_family;
    if (family != 2 && family != 10) return 0;
    struct event_t *ev = new_event(EV_ACCEPT);
    if (!ev) return 0;
    ev->family = family;
    ev->lport  = newsk->__sk_common.skc_num;
    ev->dport  = ntohs(newsk->__sk_common.skc_dport);
    if (family == 2) {
        ev->daddr4 = newsk->__sk_common.skc_daddr;
    } else {
        bpf_probe_read_kernel(&ev->daddr6, sizeof(ev->daddr6),
                              &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    events.perf_submit(ctx, ev, EV_NOFILE_SZ);
    return 0;
}

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || pid == SELF_TGID) return 0;
    struct pid_stats_t *s = stats_for(pid);
    if (s) __sync_fetch_and_add(&s->tcp_tx, (u64)size);
    return 0;
}
int trace_tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    if (copied <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || pid == SELF_TGID) return 0;
    struct pid_stats_t *s = stats_for(pid);
    if (s) __sync_fetch_and_add(&s->tcp_rx, (u64)copied);
    return 0;
}
int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || pid == SELF_TGID) return 0;
    struct pid_stats_t *s = stats_for(pid);
    if (s) __sync_fetch_and_add(&s->udp_tx, (u64)len);
    return 0;
}
"""

# tracepoint name -> compile flag.  Missing ones are simply not compiled in.
OPTIONAL_TRACEPOINTS = {
    "sys_enter_open": "HAVE_OPEN",
    "sys_enter_openat": "HAVE_OPENAT",
    "sys_enter_creat": "HAVE_CREAT",
    "sys_enter_unlink": "HAVE_UNLINK",
    "sys_enter_unlinkat": "HAVE_UNLINKAT",
    "sys_enter_rename": "HAVE_RENAME",
    "sys_enter_renameat": "HAVE_RENAMEAT",
    "sys_enter_renameat2": "HAVE_RENAMEAT2",
    "sys_enter_clone": "HAVE_CLONE",
    "sys_enter_clone3": "HAVE_CLONE3",
    "sys_exit_read": "HAVE_EXIT_READ",
    "sys_exit_write": "HAVE_EXIT_WRITE",
}
REQUIRED_TRACEPOINTS = [("sched", "sched_process_exec"), ("sched", "sched_process_fork"),
                        ("sched", "sched_process_exit"), ("raw_syscalls", "sys_enter")]

# --------------------------------------------------------------------------- #
# Syscall categories (proposal section 9: file / network / process / memory / IPC)
# --------------------------------------------------------------------------- #
FILE_SC = set("""open openat openat2 creat close close_range read write pread64 pwrite64 readv writev preadv
pwritev preadv2 pwritev2 stat fstat lstat newfstatat statx stat64 fstat64 lstat64 lseek llseek access faccessat
faccessat2 unlink unlinkat rename renameat renameat2 mkdir mkdirat rmdir chmod fchmod fchmodat chown fchown lchown
fchownat truncate ftruncate getdents getdents64 readlink readlinkat link linkat symlink symlinkat fsync fdatasync
sync syncfs sendfile copy_file_range splice tee vmsplice fcntl dup dup2 dup3 chdir fchdir getcwd mount umount2 flock
utimensat utime utimes futimesat fallocate statfs fstatfs setxattr getxattr listxattr removexattr fsetxattr fgetxattr
inotify_init inotify_init1 inotify_add_watch inotify_rm_watch fanotify_init fanotify_mark chroot pivot_root
name_to_handle_at open_by_handle_at fadvise64 readahead sync_file_range ioctl""".split())
NET_SC = set("""socket connect accept accept4 bind listen sendto recvfrom sendmsg recvmsg sendmmsg recvmmsg shutdown
getsockname getpeername setsockopt getsockopt""".split())
PROC_SC = set("""fork vfork clone clone3 execve execveat exit exit_group wait4 waitid kill tkill tgkill getpid getppid
gettid setuid setgid setreuid setregid setresuid setresgid setfsuid setfsgid getuid getgid geteuid getegid prctl
arch_prctl ptrace setsid setpgid getpgid getpgrp getsid sched_yield sched_setaffinity sched_getaffinity
sched_setscheduler sched_getscheduler sched_setparam sched_getparam sched_get_priority_max sched_get_priority_min
set_tid_address setpriority getpriority nice rt_sigaction rt_sigprocmask rt_sigreturn rt_sigsuspend rt_sigpending
rt_sigtimedwait rt_sigqueueinfo sigaltstack signal unshare setns capget capset seccomp personality
rseq getrlimit setrlimit prlimit64 getrusage times set_robust_list get_robust_list pidfd_open pidfd_send_signal
pidfd_getfd restart_syscall""".split())
MEM_SC = set("""mmap mmap2 munmap mprotect mremap brk madvise mlock mlock2 munlock mlockall munlockall msync mincore
process_vm_readv process_vm_writev memfd_create userfaultfd remap_file_pages mbind set_mempolicy get_mempolicy
migrate_pages move_pages pkey_mprotect pkey_alloc pkey_free membarrier""".split())
IPC_SC = set("""pipe pipe2 socketpair shmget shmat shmdt shmctl semget semop semctl semtimedop msgget msgsnd msgrcv msgctl
mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr eventfd eventfd2 futex futex_waitv signalfd
signalfd4 timerfd_create timerfd_settime timerfd_gettime""".split())
# Syscalls that are rarely needed by normal programs -> useful malicious-behaviour signal
SENSITIVE_SC = set("""ptrace setuid setgid setreuid setregid setresuid setresgid chroot mount umount2 init_module
finit_module delete_module kexec_load kexec_file_load capset unshare setns bpf personality process_vm_writev
process_vm_readv memfd_create pivot_root reboot swapon swapoff iopl ioperm seccomp userfaultfd""".split())
READ_SC = {"read", "pread64", "readv", "preadv", "preadv2"}
WRITE_SC = {"write", "pwrite64", "writev", "pwritev", "pwritev2"}

_CAT_CACHE: dict = {}


def categorize(name: str) -> str:
    c = _CAT_CACHE.get(name)
    if c is None:
        if name in NET_SC:
            c = "network"
        elif name in IPC_SC:
            c = "ipc"
        elif name in FILE_SC:
            c = "file"
        elif name in PROC_SC:
            c = "process"
        elif name in MEM_SC:
            c = "memory"
        else:
            c = "other"
        _CAT_CACHE[name] = c
    return c


# event type ids (must match the C enum)
EV_EXEC, EV_FORK, EV_EXIT, EV_OPEN, EV_UNLINK, EV_RENAME, EV_CONNECT, EV_ACCEPT, EV_SYSCALL = range(1, 10)
EV_NAMES = {EV_EXEC: "process_exec", EV_FORK: "process_fork", EV_EXIT: "process_exit", EV_OPEN: "file_open",
            EV_UNLINK: "file_delete", EV_RENAME: "file_rename", EV_CONNECT: "net_connect", EV_ACCEPT: "net_accept"}
CLONE_THREAD = 0x10000
O_CREAT, O_TRUNC, O_APPEND = 0o100, 0o1000, 0o2000

# --------------------------------------------------------------------------- #
# Output schemas
# --------------------------------------------------------------------------- #
EVENT_COLS = ["event_id", "instance_id", "pid", "timestamp", "event_type", "syscall_category",
              "file_identifier", "network_identifier", "metadata"]
INSTANCE_COLS = ["instance_id", "profile_id", "pid", "ppid", "parent_instance_id", "comm", "executable",
                 "executable_hash", "uid", "start_time", "end_time", "exit_code", "preexisting", "windows_written"]
HIST_COLS = ["window_id", "instance_id", "pid", "syscall", "count"]
WINDOW_COLS = [
    "window_id", "window_index", "instance_id", "profile_id", "pid", "ppid", "comm", "executable",
    "start_time", "end_time", "duration_s",
    # syscalls
    "syscall_count", "syscalls_file", "syscalls_network", "syscalls_process", "syscalls_memory", "syscalls_ipc",
    "syscalls_other", "syscalls_sensitive", "distinct_syscalls",
    # files
    "file_read_count", "file_write_count", "file_open_count", "file_open_write_count", "file_create_count",
    "file_delete_count", "file_rename_count", "unique_files", "bytes_read", "bytes_written",
    # network
    "network_count", "net_connect_count", "net_accept_count", "unique_dest_ips", "unique_dest_ports",
    "tcp_tx_bytes", "tcp_rx_bytes", "udp_tx_bytes",
    # process relations
    "child_process_count", "thread_create_count", "exec_count",
    # resources
    "cpu_usage", "memory_usage", "memory_rss_bytes", "memory_vms_bytes", "memory_percent", "num_threads",
    "num_fds", "disk_read_bytes", "disk_write_bytes", "ctx_switches_voluntary", "ctx_switches_involuntary",
    # bookkeeping / label
    "alive_at_end", "label", "label_binary", "scenario", "experiment_id"]
SYSTEM_COLS = [
    "window_index", "start_time", "end_time", "duration_s",
    "cpu_percent_total", "cpu_user", "cpu_system", "cpu_idle", "cpu_iowait", "cpu_steal", "cpu_core_max",
    "load_1m", "load_5m", "load_15m", "ctx_switches_delta", "interrupts_delta",
    "mem_total", "mem_used", "mem_available", "mem_percent", "mem_buffers", "mem_cached",
    "swap_used", "swap_percent",
    "disk_root_percent", "disk_used_percent_max", "disk_read_bytes", "disk_write_bytes",
    "disk_read_count", "disk_write_count", "disk_read_time_ms", "disk_write_time_ms",
    "net_bytes_sent", "net_bytes_recv", "net_packets_sent", "net_packets_recv",
    "net_errin", "net_errout", "net_dropin", "net_dropout",
    "conn_established", "conn_listen", "conn_total", "process_count", "tracked_instances",
    "events_received", "events_lost", "label", "label_binary", "scenario", "experiment_id"]


class CsvSink:
    def __init__(self, path: str, cols: list):
        self.cols = cols
        self.f = open(path, "w", newline="", buffering=1 << 16, encoding="utf-8")
        self.w = csv.writer(self.f)
        self.w.writerow(cols)
        self.rows = 0

    def write_row(self, row: list):
        self.w.writerow(row)
        self.rows += 1

    def write(self, d: dict):
        self.w.writerow([d.get(c, "") for c in self.cols])
        self.rows += 1

    def flush(self):
        self.f.flush()

    def close(self):
        try:
            self.f.flush()
            self.f.close()
        except Exception:
            pass


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def tracepoint_exists(group: str, name: str) -> bool:
    for root in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        if os.path.isdir(f"{root}/events/{group}/{name}"):
            return True
    return False


# --------------------------------------------------------------------------- #
# Process instance + per-window accumulator
# --------------------------------------------------------------------------- #
class Acc:
    """Event-derived counters for one process during one window."""
    __slots__ = ("c", "files", "dips", "dports")

    def __init__(self):
        self.c = collections.Counter()
        self.files, self.dips, self.dports = set(), set(), set()


class Instance:
    def __init__(self, pid, ppid, comm, exe, uid, start_ts, preexisting):
        self.instance_id = uuid.uuid4().hex
        self.pid, self.ppid, self.comm, self.exe, self.uid = pid, ppid, comm, exe, uid
        self.start_ts, self.end_ts, self.exit_code = start_ts, None, ""
        self.preexisting = preexisting
        self.parent_instance_id = ""
        self.exited = False
        self.exe_hash = None
        self.profile_id = ""
        self.acc = Acc()
        self.ps = None
        self.last_cpu = 0.0
        self.last_io = (0, 0)
        self.last_cs = (0, 0)
        self.last = dict(cpu=0.0, rss=0, vms=0, mp=0.0, thr=0, fds=0, dr=0, dw=0, cv=0, ci=0)
        self.windows_written = 0
        self.set_profile()

    def set_profile(self):
        self.profile_id = hashlib.sha1((self.exe or self.comm or "?").encode("utf-8", "replace")).hexdigest()[:12]


# --------------------------------------------------------------------------- #
# System-wide sampler (CPU / RAM / disk / network)
# --------------------------------------------------------------------------- #
class SystemSampler:
    def __init__(self):
        psutil.cpu_times_percent(interval=None)
        psutil.cpu_percent(interval=None, percpu=True)
        self.p_disk = psutil.disk_io_counters()
        self.p_net = psutil.net_io_counters()
        self.p_stats = psutil.cpu_stats()

    @staticmethod
    def _d(cur, prev, name):
        try:
            return max(getattr(cur, name) - getattr(prev, name), 0) if cur and prev else 0
        except AttributeError:
            return 0

    def sample(self) -> dict:
        r = {}
        ct = psutil.cpu_times_percent(interval=None)
        cores = psutil.cpu_percent(interval=None, percpu=True)
        r.update(cpu_user=ct.user, cpu_system=ct.system, cpu_idle=ct.idle,
                 cpu_iowait=getattr(ct, "iowait", 0.0), cpu_steal=getattr(ct, "steal", 0.0),
                 cpu_percent_total=round(100.0 - ct.idle - getattr(ct, "iowait", 0.0) * 0, 2),
                 cpu_core_max=max(cores) if cores else 0.0)
        try:
            r["load_1m"], r["load_5m"], r["load_15m"] = os.getloadavg()
        except OSError:
            pass
        st = psutil.cpu_stats()
        r["ctx_switches_delta"] = self._d(st, self.p_stats, "ctx_switches")
        r["interrupts_delta"] = self._d(st, self.p_stats, "interrupts")
        self.p_stats = st
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        r.update(mem_total=vm.total, mem_used=vm.used, mem_available=vm.available, mem_percent=vm.percent,
                 mem_buffers=getattr(vm, "buffers", 0), mem_cached=getattr(vm, "cached", 0),
                 swap_used=sw.used, swap_percent=sw.percent)
        try:
            r["disk_root_percent"] = psutil.disk_usage("/").percent
        except OSError:
            pass
        worst = 0.0
        for part in psutil.disk_partitions(all=False):
            try:
                worst = max(worst, psutil.disk_usage(part.mountpoint).percent)
            except OSError:
                continue
        r["disk_used_percent_max"] = worst
        dk = psutil.disk_io_counters()
        for k_out, k_in in (("disk_read_bytes", "read_bytes"), ("disk_write_bytes", "write_bytes"),
                            ("disk_read_count", "read_count"), ("disk_write_count", "write_count"),
                            ("disk_read_time_ms", "read_time"), ("disk_write_time_ms", "write_time")):
            r[k_out] = self._d(dk, self.p_disk, k_in)
        self.p_disk = dk
        nt = psutil.net_io_counters()
        for k_out, k_in in (("net_bytes_sent", "bytes_sent"), ("net_bytes_recv", "bytes_recv"),
                            ("net_packets_sent", "packets_sent"), ("net_packets_recv", "packets_recv"),
                            ("net_errin", "errin"), ("net_errout", "errout"),
                            ("net_dropin", "dropin"), ("net_dropout", "dropout")):
            r[k_out] = self._d(nt, self.p_net, k_in)
        self.p_net = nt
        try:
            conns = psutil.net_connections(kind="inet")
            r["conn_total"] = len(conns)
            r["conn_established"] = sum(1 for c in conns if c.status == "ESTABLISHED")
            r["conn_listen"] = sum(1 for c in conns if c.status == "LISTEN")
        except (psutil.AccessDenied, OSError):
            pass
        r["process_count"] = len(psutil.pids())
        return r


# --------------------------------------------------------------------------- #
# The collector
# --------------------------------------------------------------------------- #
class Collector:
    def __init__(self, args, bpf, run_dir, experiment_id, mono_offset, probes):
        self.args, self.b, self.dir = args, bpf, run_dir
        self.exp, self.off, self.probes = experiment_id, mono_offset, probes
        self.stop = False
        self.procs: dict = {}
        self.retired: list = []
        self.ignored: set = {os.getpid()}
        self.dead_pids: set = set()
        self.sc_prev: dict = {}
        self.st_prev: dict = {}
        self.sc_names: dict = {}
        self.exe_hash_cache: dict = {}
        self.event_id = 0
        self.win_idx = 0
        self.window_id = 0
        self.lost = 0
        self.lost_window = 0
        self.ev_window = 0
        self.ev_total = 0
        self.ev_counts = collections.Counter()
        self.only = {s for s in (args.only_comm or "").split(",") if s}
        self.excl = {s for s in (args.exclude_comm or "").split(",") if s}
        self.ign_prefix = tuple(args.ignore_path_prefix or ())
        self.salt = args.path_salt.encode()
        d = run_dir
        self.s_events = CsvSink(os.path.join(d, "telemetry_events.csv"), EVENT_COLS)
        self.s_inst = CsvSink(os.path.join(d, "process_instances.csv"), INSTANCE_COLS)
        self.s_win = CsvSink(os.path.join(d, "behaviour_windows.csv"), WINDOW_COLS)
        self.s_hist = CsvSink(os.path.join(d, "syscall_histogram.csv"), HIST_COLS)
        self.s_sys = CsvSink(os.path.join(d, "system_metrics.csv"), SYSTEM_COLS)
        self.s_trace = (CsvSink(os.path.join(d, "syscall_trace.csv"), ["ts_epoch", "pid", "tid", "syscall"])
                        if args.trace_syscalls else None)
        self.sampler = SystemSampler()
        self.win_start = time.time()
        try:
            from bcc.syscall import syscall_name
            self._syscall_name = syscall_name
        except Exception:
            self._syscall_name = None

    # ----------------------------- helpers --------------------------------- #
    def sc_name(self, nr: int) -> str:
        n = self.sc_names.get(nr)
        if n is None:
            n = f"sys_{nr}"
            if self._syscall_name:
                try:
                    raw = self._syscall_name(nr)
                    n = raw.decode() if isinstance(raw, bytes) else str(raw)
                except Exception:
                    pass
            self.sc_names[nr] = n
        return n

    def fid(self, path: str) -> str:
        if not self.args.hash_paths:
            return path
        ext = os.path.splitext(path)[1][:8]
        return hashlib.sha256(self.salt + path.encode("utf-8", "replace")).hexdigest()[:16] + ext

    def allowed(self, inst) -> bool:
        if self.only and inst.comm not in self.only:
            return False
        return inst.comm not in self.excl

    def wall(self, ktime_ns: int) -> float:
        return self.off + ktime_ns / 1e9

    @staticmethod
    def ip_of(ev) -> str:
        try:
            if ev.family == 2:
                return socket.inet_ntop(socket.AF_INET, struct.pack("<I", ev.daddr4))
            return socket.inet_ntop(socket.AF_INET6, bytes(bytearray(ev.daddr6)))
        except Exception:
            return ""

    def write_event(self, ts, inst, etype, cat, fid="", nid="", meta=None):
        if inst is None or not self.allowed(inst):
            return
        self.event_id += 1
        self.s_events.write_row([self.event_id, inst.instance_id, inst.pid, iso(ts), etype, cat, fid, nid,
                                 json.dumps(meta, separators=(",", ":")) if meta else ""])

    # --------------------------- process table ----------------------------- #
    def ensure_instance(self, pid: int, preexisting: bool = False):
        inst = self.procs.get(pid)
        if inst is not None and not inst.exited:
            return inst
        if pid in self.ignored or pid <= 0:
            return None
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                ppid, comm, ct = p.ppid(), p.name(), p.create_time()
                uid = p.uids().real
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, OSError):
                    exe = ""
                try:
                    cpu = sum(p.cpu_times()[:2])
                except Exception:
                    cpu = 0.0
                cmd = p.cmdline() if not exe else True
            if pid == 2 or ppid == 2 or (not exe and not cmd):   # kernel thread
                self.ignored.add(pid)
                return None
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            return None
        inst = Instance(pid, ppid, comm, exe, uid, ct, preexisting)
        inst.ps = p
        inst.last_cpu = cpu if preexisting else 0.0
        if preexisting:
            try:
                io = p.io_counters()
                inst.last_io = (io.read_bytes, io.write_bytes)
            except Exception:
                pass
            try:
                cs = p.num_ctx_switches()
                inst.last_cs = (cs.voluntary, cs.involuntary)
            except Exception:
                pass
        parent = self.procs.get(ppid)
        inst.parent_instance_id = parent.instance_id if parent else ""
        self.procs[pid] = inst
        return inst

    def retire_if_exited(self, pid):
        old = self.procs.get(pid)
        if old is not None and old.exited:
            self.retired.append(old)
            del self.procs[pid]

    def sync_process_table(self, now):
        """Safety net: pick up processes whose fork we missed, close ones whose exit we missed."""
        try:
            live = set(psutil.pids())
        except Exception:
            return
        for pid in live - self.procs.keys() - self.ignored:
            self.ensure_instance(pid, preexisting=True)
        self.ignored &= live | {os.getpid()}
        for pid, inst in list(self.procs.items()):
            if pid not in live and not inst.exited:
                inst.exited, inst.end_ts = True, now

    def hash_exe(self, inst):
        if inst.exe_hash is not None or self.args.no_hash_exe or not inst.exe:
            return
        cached = self.exe_hash_cache.get(inst.exe)
        if cached is not None:
            inst.exe_hash = cached
            return
        h = ""
        try:
            src = f"/proc/{inst.pid}/exe" if not inst.exited else inst.exe
            if os.path.getsize(src) <= 256 * 1024 * 1024:
                m = hashlib.sha256()
                with open(src, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        m.update(chunk)
                h = m.hexdigest()
        except OSError:
            h = ""
        inst.exe_hash = h
        if h:
            self.exe_hash_cache[inst.exe] = h

    # ------------------------------ eBPF events ---------------------------- #
    def on_lost(self, n):
        self.lost += n
        self.lost_window += n

    def on_event(self, cpu, data, size):
        ev = self.b["events"].event(data)
        t = ev.type
        self.ev_total += 1
        self.ev_window += 1
        if t == EV_SYSCALL:
            if self.s_trace:
                if self.only and ev.comm.decode(errors="replace") not in self.only:
                    return
                self.s_trace.write_row([f"{self.wall(ev.ts):.6f}", ev.pid, ev.tid, self.sc_name(ev.nr)])
            return
        self.ev_counts[EV_NAMES.get(t, str(t))] += 1
        ts = self.wall(ev.ts)
        try:
            if t == EV_FORK:
                self.h_fork(ev, ts)
            elif t == EV_EXEC:
                self.h_exec(ev, ts)
            elif t == EV_EXIT:
                self.h_exit(ev, ts)
            elif t == EV_OPEN:
                self.h_open(ev, ts)
            elif t == EV_UNLINK:
                self.h_unlink(ev, ts)
            elif t == EV_RENAME:
                self.h_rename(ev, ts)
            elif t in (EV_CONNECT, EV_ACCEPT):
                self.h_net(ev, ts, t)
        except Exception as e:  # never let a parsing bug kill the collection
            print(f"[warn] event handler error: {e!r}", file=sys.stderr)

    def h_fork(self, ev, ts):
        parent = self.ensure_instance(ev.ppid)
        if ev.flags & CLONE_THREAD:                         # thread, not a child process
            if parent:
                parent.acc.c["thread_create"] += 1
            return
        if ev.ppid == 2:                                    # kthreadd child
            self.ignored.add(ev.pid)
            return
        self.retire_if_exited(ev.pid)
        child = Instance(ev.pid, ev.ppid, ev.comm.decode(errors="replace"),
                         parent.exe if parent else "", ev.uid, ts, False)
        child.parent_instance_id = parent.instance_id if parent else ""
        self.procs[ev.pid] = child
        self.ignored.discard(ev.pid)
        if parent:
            parent.acc.c["child_process"] += 1
        self.write_event(ts, parent or child, "process_fork", "process", meta={
            "child_pid": ev.pid, "child_instance_id": child.instance_id, "child_comm": child.comm})

    def h_exec(self, ev, ts):
        inst = self.ensure_instance(ev.pid)
        if inst is None:
            return
        fname = ev.fname.decode(errors="replace")
        try:
            exe = os.readlink(f"/proc/{ev.pid}/exe")
        except OSError:
            exe = fname
        inst.exe, inst.comm, inst.exe_hash = exe, ev.comm.decode(errors="replace"), None
        inst.ppid = ev.ppid or inst.ppid
        inst.set_profile()
        inst.acc.c["exec"] += 1
        self.write_event(ts, inst, "process_exec", "process", fid=self.fid(exe),
                         meta={"filename": self.fid(fname), "ppid": inst.ppid})

    def h_exit(self, ev, ts):
        inst = self.procs.get(ev.pid)
        if inst is None or inst.exited:
            return
        inst.exited, inst.end_ts, inst.exit_code = True, ts, ev.flags
        self.write_event(ts, inst, "process_exit", "process", meta={"exit_code": ev.flags})

    def h_open(self, ev, ts):
        inst = self.ensure_instance(ev.pid)
        if inst is None:
            return
        path = ev.fname.decode(errors="replace")
        if self.ign_prefix and path.startswith(self.ign_prefix):
            return
        fl = ev.flags
        acc_mode = fl & 3
        write = acc_mode in (1, 2) or bool(fl & (O_TRUNC | O_APPEND))
        c = inst.acc.c
        c["file_open"] += 1
        ops = ["write" if acc_mode == 1 else "readwrite" if acc_mode == 2 else "read"]
        if write:
            c["file_open_write"] += 1
        if fl & O_CREAT:
            c["file_create"] += 1
            ops.append("create")
        if fl & O_TRUNC:
            ops.append("truncate")
        if fl & O_APPEND:
            ops.append("append")
        fid = self.fid(path)
        inst.acc.files.add(fid)
        self.write_event(ts, inst, "file_open", "file", fid=fid, meta={"ops": ops, "flags": fl})

    def h_unlink(self, ev, ts):
        inst = self.ensure_instance(ev.pid)
        if inst is None:
            return
        inst.acc.c["file_delete"] += 1
        fid = self.fid(ev.fname.decode(errors="replace"))
        inst.acc.files.add(fid)
        self.write_event(ts, inst, "file_delete", "file", fid=fid, meta={"rmdir": bool(ev.flags & 0x200)})

    def h_rename(self, ev, ts):
        inst = self.ensure_instance(ev.pid)
        if inst is None:
            return
        inst.acc.c["file_rename"] += 1
        old = self.fid(ev.fname.decode(errors="replace"))
        inst.acc.files.add(old)
        self.write_event(ts, inst, "file_rename", "file", fid=old,
                         meta={"new": self.fid(ev.fname2.decode(errors="replace"))})

    def h_net(self, ev, ts, t):
        inst = self.ensure_instance(ev.pid)
        if inst is None:
            return
        ip = self.ip_of(ev)
        key = "net_connect" if t == EV_CONNECT else "net_accept"
        inst.acc.c[key] += 1
        inst.acc.dips.add(ip)
        inst.acc.dports.add(ev.dport)
        fam = "ipv4" if ev.family == 2 else "ipv6"
        self.write_event(ts, inst, EV_NAMES[t], "network", nid=f"{ip}:{ev.dport}",
                         meta={"family": fam, "local_port": ev.lport,
                               "direction": "outbound" if t == EV_CONNECT else "inbound"})

    # ------------------------- kernel map draining ------------------------- #
    def read_syscall_deltas(self) -> dict:
        cur, out = {}, collections.defaultdict(dict)
        for k, v in self.b["sc_counts"].items():
            cur[(k.pid, k.nr)] = v.value
        for key, val in cur.items():
            d = val - self.sc_prev.get(key, 0)
            if d < 0:
                d = val
            if d:
                out[key[0]][key[1]] = d
        self.sc_prev = cur
        return out

    def read_pid_stats(self) -> dict:
        cur, out = {}, {}
        names = ("rd_bytes", "wr_bytes", "tcp_tx", "tcp_rx", "udp_tx")
        for k, v in self.b["pid_stats"].items():
            cur[k.value] = tuple(getattr(v, n) for n in names)
        for pid, vals in cur.items():
            prev = self.st_prev.get(pid, (0,) * 5)
            d = tuple(a - b if a >= b else a for a, b in zip(vals, prev))
            if any(d):
                out[pid] = dict(zip(names, d))
        self.st_prev = cur
        return out

    def purge_dead(self):
        """Remove map entries of exited pids so a recycled PID starts from zero."""
        if not self.dead_pids:
            return
        import ctypes as ct
        sc_tbl, st_tbl = self.b["sc_counts"], self.b["pid_stats"]
        for key in [k for k in self.sc_prev if k[0] in self.dead_pids and k[0] not in self.procs]:
            try:
                del sc_tbl[sc_tbl.Key(key[0], key[1])]
            except Exception:
                pass
            self.sc_prev.pop(key, None)
        for pid in [p for p in self.st_prev if p in self.dead_pids and p not in self.procs]:
            try:
                del st_tbl[ct.c_uint(pid)]
            except Exception:
                pass
            self.st_prev.pop(pid, None)
        self.dead_pids.clear()

    # ------------------------------ resources ------------------------------ #
    def sample_resources(self, inst, start, end) -> dict:
        r = inst.last
        if inst.exited:
            return dict(r, cpu=0.0, dr=0, dw=0, cv=0, ci=0)
        try:
            ps = inst.ps or psutil.Process(inst.pid)
            inst.ps = ps
            with ps.oneshot():
                ct, mi = ps.cpu_times(), ps.memory_info()
                thr, mp, cs = ps.num_threads(), ps.memory_percent(), ps.num_ctx_switches()
                try:
                    fds = ps.num_fds()
                except Exception:
                    fds = r["fds"]
                try:
                    io = ps.io_counters()
                    io_t = (io.read_bytes, io.write_bytes)
                except Exception:
                    io_t = inst.last_io
            tot = ct.user + ct.system
            eff = max(end - max(start, inst.start_ts), 1e-3)
            cpu = max(tot - inst.last_cpu, 0.0) / eff * 100.0
            res = dict(cpu=round(cpu, 3), rss=mi.rss, vms=mi.vms, mp=round(mp, 4), thr=thr, fds=fds,
                       dr=max(io_t[0] - inst.last_io[0], 0), dw=max(io_t[1] - inst.last_io[1], 0),
                       cv=max(cs.voluntary - inst.last_cs[0], 0), ci=max(cs.involuntary - inst.last_cs[1], 0))
            inst.last_cpu, inst.last_io, inst.last_cs = tot, io_t, (cs.voluntary, cs.involuntary)
            inst.last = res
            return res
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            inst.exited, inst.end_ts = True, inst.end_ts or end
            return dict(r, cpu=0.0, dr=0, dw=0, cv=0, ci=0)
        except psutil.AccessDenied:
            return dict(r, cpu=0.0, dr=0, dw=0, cv=0, ci=0)

    def current_label(self):
        label, scen = self.args.label, self.args.scenario
        if self.args.label_file:
            try:
                with open(self.args.label_file, "r", encoding="utf-8") as f:
                    line = f.readline().strip()
                if line:
                    label, _, s = line.partition(":")
                    scen = s or scen
            except OSError:
                pass
        low = label.lower()
        binary = 0 if low in ("benign", "normal", "0") else "" if low in ("unlabeled", "unlabelled", "") else 1
        return label, binary, scen

    # ------------------------------ windowing ------------------------------ #
    def flush_window(self, end):
        start = self.win_start
        dur = max(end - start, 1e-6)
        self.win_idx += 1
        label, lbin, scen = self.current_label()
        self.sync_process_table(end)
        sc, st = self.read_syscall_deltas(), self.read_pid_stats()
        for pid in set(sc) | set(st):
            self.ensure_instance(pid)

        sysrow = self.sampler.sample()
        sysrow.update(window_index=self.win_idx, start_time=iso(start), end_time=iso(end),
                      duration_s=round(dur, 3), tracked_instances=len(self.procs),
                      events_received=self.ev_window, events_lost=self.lost_window,
                      label=label, label_binary=lbin, scenario=scen, experiment_id=self.exp)
        self.s_sys.write(sysrow)

        targets = list(self.procs.values()) + self.retired
        written = 0
        for inst in targets:
            acc, inst.acc = inst.acc, Acc()
            if not self.allowed(inst):
                continue
            hist = sc.get(inst.pid, {})
            pst = st.get(inst.pid, {})
            res = self.sample_resources(inst, start, end)
            total = sum(hist.values())
            c = acc.c
            active = (total or sum(c.values()) or res["cpu"] > 0 or any(pst.values()) or res["dr"] or res["dw"])
            if not active and not self.args.include_idle:
                continue
            cats, rd, wr, sens = collections.Counter(), 0, 0, 0
            named = {}
            for nr, cnt in hist.items():
                name = self.sc_name(nr)
                named[name] = named.get(name, 0) + cnt
                cats[categorize(name)] += cnt
                if name in READ_SC:
                    rd += cnt
                elif name in WRITE_SC:
                    wr += cnt
                if name in SENSITIVE_SC:
                    sens += cnt
            self.hash_exe(inst)
            self.window_id += 1
            wid = self.window_id
            self.s_win.write(dict(
                window_id=wid, window_index=self.win_idx, instance_id=inst.instance_id,
                profile_id=inst.profile_id, pid=inst.pid, ppid=inst.ppid, comm=inst.comm, executable=inst.exe,
                start_time=iso(max(start, inst.start_ts)), end_time=iso(end), duration_s=round(dur, 3),
                syscall_count=total, syscalls_file=cats["file"], syscalls_network=cats["network"],
                syscalls_process=cats["process"], syscalls_memory=cats["memory"], syscalls_ipc=cats["ipc"],
                syscalls_other=cats["other"], syscalls_sensitive=sens, distinct_syscalls=len(named),
                file_read_count=rd, file_write_count=wr, file_open_count=c["file_open"],
                file_open_write_count=c["file_open_write"], file_create_count=c["file_create"],
                file_delete_count=c["file_delete"], file_rename_count=c["file_rename"],
                unique_files=len(acc.files), bytes_read=pst.get("rd_bytes", 0), bytes_written=pst.get("wr_bytes", 0),
                network_count=c["net_connect"] + c["net_accept"], net_connect_count=c["net_connect"],
                net_accept_count=c["net_accept"], unique_dest_ips=len(acc.dips), unique_dest_ports=len(acc.dports),
                tcp_tx_bytes=pst.get("tcp_tx", 0), tcp_rx_bytes=pst.get("tcp_rx", 0), udp_tx_bytes=pst.get("udp_tx", 0),
                child_process_count=c["child_process"], thread_create_count=c["thread_create"], exec_count=c["exec"],
                cpu_usage=res["cpu"], memory_usage=round(res["rss"] / 1048576, 3), memory_rss_bytes=res["rss"],
                memory_vms_bytes=res["vms"], memory_percent=res["mp"], num_threads=res["thr"], num_fds=res["fds"],
                disk_read_bytes=res["dr"], disk_write_bytes=res["dw"], ctx_switches_voluntary=res["cv"],
                ctx_switches_involuntary=res["ci"], alive_at_end=0 if inst.exited else 1,
                label=label, label_binary=lbin, scenario=scen, experiment_id=self.exp))
            for name, cnt in sorted(named.items()):
                self.s_hist.write_row([wid, inst.instance_id, inst.pid, name, cnt])
            inst.windows_written += 1
            written += 1

        # finalise exited instances
        for inst in targets:
            if inst.exited:
                self.write_instance(inst)
                if self.procs.get(inst.pid) is inst:
                    del self.procs[inst.pid]
                self.dead_pids.add(inst.pid)
        self.retired.clear()
        self.purge_dead()
        for s in (self.s_events, self.s_inst, self.s_win, self.s_hist, self.s_sys, self.s_trace):
            if s:
                s.flush()
        if not self.args.quiet:
            print(f"[window {self.win_idx:>4}] {iso(end)[11:19]}  rows={written:<4} procs={len(self.procs):<4} "
                  f"events={self.ev_window:<6} lost={self.lost_window:<4} cpu={sysrow['cpu_percent_total']:>5.1f}% "
                  f"mem={sysrow['mem_percent']:>4.1f}% label={label}", file=sys.stderr)
        self.win_start = end
        self.ev_window = self.lost_window = 0

    def write_instance(self, inst):
        self.hash_exe(inst)
        self.s_inst.write_row([
            inst.instance_id, inst.profile_id, inst.pid, inst.ppid, inst.parent_instance_id, inst.comm, inst.exe,
            inst.exe_hash or "", inst.uid, iso(inst.start_ts), iso(inst.end_ts) if inst.end_ts else "",
            inst.exit_code, int(inst.preexisting), inst.windows_written])

    # -------------------------------- main loop ---------------------------- #
    def run(self):
        for p in psutil.process_iter():
            self.ensure_instance(p.pid, preexisting=True)
        self.b["events"].open_perf_buffer(self.on_event, page_cnt=self.args.perf_pages, lost_cb=self.on_lost)
        t_end = time.time() + self.args.duration if self.args.duration > 0 else None
        next_tick = self.win_start + self.args.window
        while not self.stop:
            now = time.time()
            if t_end is not None and now >= t_end:
                break
            wait_ms = max(1, int(min(next_tick - now, 0.2) * 1000))
            self.b.perf_buffer_poll(timeout=wait_ms)
            if time.time() >= next_tick:
                self.flush_window(time.time())
                next_tick = self.win_start + self.args.window

    def finish(self):
        try:
            self.b.perf_buffer_poll(timeout=50)
        except Exception:
            pass
        self.flush_window(time.time())
        for inst in list(self.procs.values()):
            self.write_instance(inst)
        for s in (self.s_events, self.s_inst, self.s_win, self.s_hist, self.s_sys, self.s_trace):
            if s:
                s.close()


# --------------------------------------------------------------------------- #
# Reproducibility metadata (proposal section 50)
# --------------------------------------------------------------------------- #
def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""


def build_metadata(args, exp, probes, status, extra=None) -> dict:
    cpu_model = ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith(("model name", "hardware")):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    os_pretty = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_pretty = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    md = {
        "experiment_id": exp, "status": status, "label": args.label, "scenario": args.scenario,
        "random_seed": args.seed, "window_seconds": args.window, "argv": sys.argv,
        "os": os_pretty, "kernel": platform.release(), "kernel_version": platform.version(),
        "machine": platform.machine(), "hostname_hash": hashlib.sha256(socket.gethostname().encode()).hexdigest()[:12],
        "python": platform.python_version(), "psutil": psutil.__version__,
        "bcc_package": sh("dpkg-query -W -f='${Version}' python3-bpfcc 2>/dev/null") or sh("rpm -q bcc 2>/dev/null"),
        "bpf_config": {"unprivileged_bpf_disabled": sh("cat /proc/sys/kernel/unprivileged_bpf_disabled"),
                       "perf_buffer_pages": args.perf_pages},
        "hardware": {"cpu_model": cpu_model, "cpu_logical": psutil.cpu_count(), "cpu_physical": psutil.cpu_count(False),
                     "ram_bytes": psutil.virtual_memory().total, "swap_bytes": psutil.swap_memory().total},
        "probes": probes, "git_commit": sh("git rev-parse HEAD 2>/dev/null"),
        "privacy": {"hash_paths": args.hash_paths, "store_cmdline": False},
    }
    if extra:
        md.update(extra)
    return md


# --------------------------------------------------------------------------- #
def parse_args():
    ap = argparse.ArgumentParser(description="Chronicle eBPF dataset collector (run as root).",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--out", default="./chronicle_dataset", help="output root directory")
    ap.add_argument("--experiment-id", default=None, help="default: exp-<UTC time>-<label>")
    ap.add_argument("--label", default="unlabeled", help="benign | malicious | <any string> (0 for benign/normal, 1 otherwise)")
    ap.add_argument("--scenario", default="ambient", help="free-text scenario name, e.g. backup_job, ransomware_sim")
    ap.add_argument("--label-file", default=None,
                    help="file read every window; first line 'label[:scenario]' overrides --label at runtime "
                         "(lets a workload switch benign->malicious mid-run)")
    ap.add_argument("--window", type=float, default=5.0, help="behaviour-window length in seconds")
    ap.add_argument("--duration", type=float, default=0, help="seconds to collect (0 = until Ctrl+C)")
    ap.add_argument("--seed", type=int, default=42, help="recorded in metadata for reproducibility")
    ap.add_argument("--include-idle", action="store_true", help="also write rows for completely idle processes")
    ap.add_argument("--only-comm", default="", help="comma list: only record these process names")
    ap.add_argument("--exclude-comm", default="", help="comma list: skip these process names")
    ap.add_argument("--ignore-path-prefix", action="append", default=[],
                    help="skip file_open events under this prefix (repeatable), e.g. /proc/ /sys/")
    ap.add_argument("--trace-syscalls", action="store_true",
                    help="also dump the raw syscall sequence (ADFA-LD style). VERY high volume.")
    ap.add_argument("--hash-paths", action="store_true", help="store salted hashes instead of file paths")
    ap.add_argument("--path-salt", default="chronicle", help="salt for --hash-paths")
    ap.add_argument("--no-hash-exe", action="store_true", help="skip SHA-256 of executables")
    ap.add_argument("--perf-pages", type=int, default=512, help="perf buffer pages per CPU (power of 2)")
    ap.add_argument("--quiet", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    if not sys.platform.startswith("linux"):
        sys.exit("This collector only runs on Linux.")
    if os.geteuid() != 0:
        sys.exit("Run as root:  sudo python3 chronicle_collector.py ...")
    try:
        from bcc import BPF
    except ImportError:
        sys.exit("BCC python bindings not found.\n  Ubuntu/Debian: sudo apt install bpfcc-tools python3-bpfcc "
                 "linux-headers-$(uname -r)\n  (if you use a venv, create it with --system-site-packages)")

    for g, n in REQUIRED_TRACEPOINTS:
        if not tracepoint_exists(g, n):
            sys.exit(f"Required tracepoint {g}:{n} not found. Is tracefs mounted? (mount -t tracefs nodev /sys/kernel/tracing)")

    exp = args.experiment_id or f"exp-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{args.label}"
    run_dir = os.path.join(args.out, exp)
    os.makedirs(run_dir, exist_ok=True)

    cflags, probes = [f"-DSELF_TGID={os.getpid()}"], {}
    for tp, flag in OPTIONAL_TRACEPOINTS.items():
        ok = tracepoint_exists("syscalls", tp)
        probes[f"tracepoint:syscalls:{tp}"] = "attached" if ok else "not available on this kernel"
        if ok:
            cflags.append(f"-D{flag}")
    if args.trace_syscalls:
        cflags.append("-DTRACE_SEQ")

    print(f"[chronicle] compiling eBPF programs (experiment {exp}) ...", file=sys.stderr)
    b = BPF(text=BPF_SOURCE, cflags=cflags)

    def attach(kind, event, fn):
        try:
            (b.attach_kprobe if kind == "k" else b.attach_kretprobe)(event=event, fn_name=fn)
            probes[f"{'kprobe' if kind == 'k' else 'kretprobe'}:{event}"] = "attached"
        except Exception as e:
            probes[f"{'kprobe' if kind == 'k' else 'kretprobe'}:{event}"] = f"FAILED: {e}"
            print(f"[warn] could not attach {event}: {e}", file=sys.stderr)

    attach("k", "tcp_v4_connect", "trace_connect_entry")
    attach("r", "tcp_v4_connect", "trace_connect_v4_return")
    attach("k", "tcp_v6_connect", "trace_connect_entry")
    attach("r", "tcp_v6_connect", "trace_connect_v6_return")
    attach("r", "inet_csk_accept", "trace_accept_return")
    attach("k", "tcp_sendmsg", "trace_tcp_sendmsg")
    attach("k", "tcp_cleanup_rbuf", "trace_tcp_cleanup_rbuf")
    attach("k", "udp_sendmsg", "trace_udp_sendmsg")
    attach("k", "udpv6_sendmsg", "trace_udp_sendmsg")

    # monotonic -> wall clock offset (bpf_ktime_get_ns == CLOCK_MONOTONIC)
    offs = []
    for _ in range(5):
        offs.append(time.time() - time.monotonic())
    mono_offset = sorted(offs)[2]

    col = Collector(args, b, run_dir, exp, mono_offset, probes)
    meta_path = os.path.join(run_dir, "metadata.json")
    started = time.time()
    with open(meta_path, "w") as f:
        json.dump(build_metadata(args, exp, probes, "running", {"started_at": iso(started)}), f, indent=2)

    def _stop(signum, frame):
        col.stop = True
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    print(f"[chronicle] collecting -> {run_dir}   (window={args.window}s, label={args.label}, "
          f"scenario={args.scenario}). Ctrl+C to stop.", file=sys.stderr)
    try:
        col.run()
    finally:
        col.finish()
        ended = time.time()
        with open(meta_path, "w") as f:
            json.dump(build_metadata(args, exp, probes, "completed", {
                "started_at": iso(started), "ended_at": iso(ended), "runtime_seconds": round(ended - started, 2),
                "windows": col.win_idx, "events_received": col.ev_total, "events_lost": col.lost,
                "event_counts": dict(col.ev_counts),
                "rows": {"telemetry_events": col.s_events.rows, "process_instances": col.s_inst.rows,
                         "behaviour_windows": col.s_win.rows, "syscall_histogram": col.s_hist.rows,
                         "system_metrics": col.s_sys.rows}}), f, indent=2)
        print(f"[chronicle] done. {col.win_idx} windows, {col.s_win.rows} behaviour rows, "
              f"{col.s_events.rows} events, {col.lost} events lost.\n[chronicle] output: {run_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
