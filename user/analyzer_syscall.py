#! /usr/bin/env python

import re
import analyzer_transaction
import argparse

syscalltable = ["sys_read", "sys_write", "sys_open", "sys_close", "sys_stat",
                "sys_fstat", "sys_lstat", "sys_poll", "sys_lseek", "sys_mmap",
                "sys_mprotect", "sys_munmap", "sys_brk", "sys_rt_sigaction",
                "sys_rt_sigprocmask", "sys_rt_sigreturn", "sys_ioctl",
                "sys_pread64", "sys_pwrite64", "sys_readv", "sys_writev",
                "sys_access", "sys_pipe", "sys_select", "sys_sched_yield",
                "sys_mremap", "sys_msync", "sys_mincore", "sys_madvise",
                "sys_shmget", "sys_shmat", "sys_shmctl", "sys_dup", "sys_dup2",
                "sys_pause", "sys_nanosleep", "sys_getitimer", "sys_alarm",
                "sys_setitimer", "sys_getpid", "sys_sendfile", "sys_socket",
                "sys_connect", "sys_accept", "sys_sendto", "sys_recvfrom",
                "sys_sendmsg", "sys_recvmsg", "sys_shutdown", "sys_bind",
                "sys_listen", "sys_getsockname", "sys_getpeername",
                "sys_socketpair", "sys_setsockopt", "sys_getsockopt",
                "sys_clone", "sys_fork", "sys_vfork", "sys_execve", "sys_exit",
                "sys_wait4", "sys_kill", "sys_uname", "sys_semget",
                "sys_semop", "sys_semctl", "sys_shmdt", "sys_msgget",
                "sys_msgsnd", "sys_msgrcv", "sys_msgctl", "sys_fcntl",
                "sys_flock", "sys_fsync", "sys_fdatasync", "sys_truncate",
                "sys_ftruncate", "sys_getdents", "sys_getcwd", "sys_chdir",
                "sys_fchdir", "sys_rename", "sys_mkdir", "sys_rmdir",
                "sys_creat", "sys_link", "sys_unlink", "sys_symlink",
                "sys_readlink", "sys_chmod", "sys_fchmod", "sys_chown",
                "sys_fchown", "sys_lchown", "sys_umask", "sys_gettimeofday",
                "sys_getrlimit", "sys_getrusage", "sys_sysinfo", "sys_times",
                "sys_ptrace", "sys_getuid", "sys_syslog", "sys_getgid",
                "sys_setuid", "sys_setgid", "sys_geteuid", "sys_getegid",
                "sys_setpgid", "sys_getppid", "sys_getpgrp", "sys_setsid",
                "sys_setreuid", "sys_setregid", "sys_getgroups",
                "sys_setgroups", "sys_setresuid", "sys_getresuid",
                "sys_setresgid", "sys_getresgid", "sys_getpgid",
                "sys_setfsuid", "sys_setfsgid", "sys_getsid", "sys_capget",
                "sys_capset", "sys_rt_sigpending", "sys_rt_sigtimedwait",
                "sys_rt_sigqueueinfo", "sys_rt_sigsuspend", "sys_sigaltstack",
                "sys_utime", "sys_mknod", "sys_uselib", "sys_personality",
                "sys_ustat", "sys_statfs", "sys_fstatfs", "sys_sysfs",
                "sys_getpriority", "sys_setpriority", "sys_sched_setparam",
                "sys_sched_getparam", "sys_sched_setscheduler",
                "sys_sched_getscheduler", "sys_sched_get_priority_max",
                "sys_sched_get_priority_min", "sys_sched_rr_get_interval",
                "sys_mlock", "sys_munlock", "sys_mlockall", "sys_munlockall",
                "sys_vhangup", "sys_modify_ldt", "sys_pivot_root",
                "sys__sysctl", "sys_prctl", "sys_arch_prctl", "sys_adjtimex",
                "sys_setrlimit", "sys_chroot", "sys_sync", "sys_acct",
                "sys_settimeofday", "sys_mount", "sys_umount2", "sys_swapon",
                "sys_swapoff", "sys_reboot", "sys_sethostname",
                "sys_setdomainname", "sys_iopl", "sys_ioperm",
                "sys_create_module", "sys_init_module", "sys_delete_module",
                "sys_get_kernel_syms", "sys_query_module", "sys_quotactl",
                "sys_nfsservctl", "sys_getpmsg", "sys_putpmsg",
                "sys_afs_syscall", "sys_tuxcall", "sys_security", "sys_gettid",
                "sys_readahead", "sys_setxattr", "sys_lsetxattr",
                "sys_fsetxattr", "sys_getxattr", "sys_lgetxattr",
                "sys_fgetxattr", "sys_listxattr", "sys_llistxattr",
                "sys_flistxattr", "sys_removexattr", "sys_lremovexattr",
                "sys_fremovexattr", "sys_tkill", "sys_time", "sys_futex",
                "sys_sched_setaffinity", "sys_sched_getaffinity",
                "sys_set_thread_area", "sys_io_setup", "sys_io_destroy",
                "sys_io_getevents", "sys_io_submit", "sys_io_cancel",
                "sys_get_thread_area", "sys_lookup_dcookie",
                "sys_epoll_create", "sys_epoll_ctl_old", "sys_epoll_wait_old",
                "sys_remap_file_pages", "sys_getdents64",
                "sys_set_tid_address", "sys_restart_syscall", "sys_semtimedop",
                "sys_fadvise64", "sys_timer_create", "sys_timer_settime",
                "sys_timer_gettime", "sys_timer_getoverrun",
                "sys_timer_delete", "sys_clock_settime", "sys_clock_gettime",
                "sys_clock_getres", "sys_clock_nanosleep", "sys_exit_group",
                "sys_epoll_wait", "sys_epoll_ctl", "sys_tgkill", "sys_utimes",
                "sys_vserver", "sys_mbind", "sys_set_mempolicy",
                "sys_get_mempolicy", "sys_mq_open", "sys_mq_unlink",
                "sys_mq_timedsend", "sys_mq_timedreceive", "sys_mq_notify",
                "sys_mq_getsetattr", "sys_kexec_load", "sys_waitid",
                "sys_add_key", "sys_request_key", "sys_keyctl",
                "sys_ioprio_set", "sys_ioprio_get", "sys_inotify_init",
                "sys_inotify_add_watch", "sys_inotify_rm_watch",
                "sys_migrate_pages", "sys_openat", "sys_mkdirat",
                "sys_mknodat", "sys_fchownat", "sys_futimesat",
                "sys_newfstatat", "sys_unlinkat", "sys_renameat", "sys_linkat",
                "sys_symlinkat", "sys_readlinkat", "sys_fchmodat",
                "sys_faccessat", "sys_pselect6", "sys_ppoll", "sys_unshare",
                "sys_set_robust_list", "sys_get_robust_list", "sys_splice",
                "sys_tee", "sys_sync_file_range", "sys_vmsplice",
                "sys_move_pages", "sys_utimensat", "sys_epoll_pwait",
                "sys_signalfd", "sys_timerfd_create", "sys_eventfd",
                "sys_fallocate", "sys_timerfd_settime", "sys_timerfd_gettime",
                "sys_accept4", "sys_signalfd4", "sys_eventfd2",
                "sys_epoll_create1", "sys_dup3", "sys_pipe2",
                "sys_inotify_init1", "sys_preadv", "sys_pwritev",
                "sys_rt_tgsigqueueinfo", "sys_perf_event_open", "sys_recvmmsg",
                "sys_fanotify_init", "sys_fanotify_mark", "sys_prlimit64",
                "sys_name_to_handle_at", "sys_open_by_handle_at",
                "sys_clock_adjtime", "sys_syncfs", "sys_sendmmsg", "sys_setns",
                "sys_getcpu", "sys_process_vm_readv", "sys_process_vm_writev",
                "sys_kcmp", "sys_finit_module", "sys_sched_setattr",
                "sys_sched_getattr", "sys_renameat2", "sys_seccomp",
                "sys_getrandom", "sys_memfd_create", "sys_kexec_file_load",
                "sys_bpf", "stub_execveat", "userfaultfd", "membarrier",
                "mlock2", "copy_file_range", "preadv2", "pwritev2"]


class AnalyzerSyscall(analyzer_transaction.Analyzer):
    def __init__(self, f, target_vcpu):
        super(AnalyzerSyscall, self).__init__(f, target_vcpu)
        self.p_setcr3 = re.compile("cr_write 3")
        self.p_syscall = re.compile("kvm_linux_em_syscall")
        self.p_sysret = re.compile("kvm_em_sysret")
        self.p_execve = re.compile("kvm_execve_filename")
        self.p_exit_cr3 = re.compile("kvm_exit_cr3")
        self.p_extract_filename = re.compile(" |\n")
        self.systracs = []

    def behavior(self, exit_reason):
        transaction = {}
        events = [exit_reason]
        while True:
            s = self.f.readline()
            if not s:
                break
            elif self.is_kvm_entry(s):
                break
            else:
                event = self.extract_event(s)
                events.append(event)
            if self.is_setcr3(s):
                transaction['setcr3'] = self.extract_setcr3(s)
            elif self.is_syscall(s):
                transaction['syscall'] = self.extract_syscall(s)
            elif self.is_sysret(s):
                transaction['sysret'] = self.extract_sysret(s)
            elif self.is_execve(s):
                transaction['execve'] = self.extract_execve(s)
            elif self.is_exit_cr3(s):
                cr3_data = self.extract_exit_cr3(s)
                transaction["cr3"] = cr3_data[0]
                transaction["cpl"] = cr3_data[1][:-1]
        transaction["events"] = events
        return transaction

    def extract_setcr3(self, s):
        ms = self.p_event.split(s)
        setcr3 = ["set cr3", ms[2].split(" ")[17][:-1]]
        self.systracs.append(setcr3)
        return setcr3[1]

    def extract_syscall(self, s):
        val = ["syscall"]
        val.append(syscalltable[int(self.extract_rax_value(s), 16)])
        self.systracs.append(val)
        return val[1]

    def extract_sysret(self, s):
        val = ["sysret"]
        val.append(self.extract_rax_value(s, sysret=True))
        self.systracs.append(val)
        return val[1]

    def extract_execve(self, s):
        ms = self.p_event.split(s)
        if ms:
            ret_str = []
            filename = self.p_extract_filename.split(ms[2])[2:-2]
            for c in filename:
                ret_str.append(chr(int("0x{}".format(c), 16)))
            execve = ["execve", "".join(ret_str)]
            self.systracs.append(execve)
            return execve

    def extract_rax_value(self, s, sysret=False):
        ms = self.p_event.split(s)
        if ms:
            if sysret:
                rax_str = ms[2].split(" ")[8]
                rax_str = rax_str[:-1]
            else:
                rax_str = ms[2].split(" ")[1]
            return rax_str

    def extract_exit_cr3(self, s):
        ms = self.p_event.split(s)
        if ms:
            components = ms[2].split(" ")
            return (components[10], components[12])

    def is_setcr3(self, s):
        return self.p_setcr3.search(s)

    def is_syscall(self, s):
        return self.p_syscall.search(s)

    def is_sysret(self, s):
        return self.p_sysret.search(s)

    def is_execve(self, s):
        return self.p_execve.search(s)

    def is_exit_cr3(self, s):
        return self.p_exit_cr3.search(s)


def show_transactions(tracs, cr3_filter=None, nmi=False):
    for t in tracs:
        if cr3_filter and not cr3_filter == t['cr3']:
            continue
        if nmi and "EXCEPTION_NMI" in t['events']:
            continue
        print(repr(t))


def show_syscall_trace(tracs):
    for t in tracs:
        print(repr(t))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', metavar='filename')
    parser.add_argument('target_vcpu', metavar='target vcpu')
    parser.add_argument('--cr3', nargs='?', metavar='cr3 filtering')
    parser.add_argument('--syscall', action='store_true')
    parser.add_argument('--ignore_nmi', action='store_true')

    args = parser.parse_args()
    with open(args.filename) as f:
        a = AnalyzerSyscall(f, args.target_vcpu)
        a.create_transactions()
        show_transactions(a.tracs, cr3_filter=args.cr3, nmi=args.ignore_nmi)
        if args.syscall:
            show_syscall_trace(a.systracs)
