#! /usr/bin/env python

import re
import analyzer_transaction
import argparse
from analyzer_syscall_table import syscalltable


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
