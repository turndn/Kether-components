#! /usr/bin/env python

import re
import analyzer_transaction
import argparse
from analyzer_syscall_table import syscalltable
from analyzer_msr_table import msr_table


class transactions_syscall(dict):
    def __init__(self, **kwarg):
        super(dict, self).__init__(**kwarg)
        self.item_table = {
            'syscall': [['syscall', 'sysret'], self.repr_items],
            'file': [['execve', 'open'], self.repr_items],
            'set_cr3': [['set_cr3'], self.repr_items],
            'cpuid': [['cpuid'], self.repr_items],
            'msr': [['msr_read', 'msr_write'], self.repr_msr],
        }

    def __repr__(self):
        detail = []
        for key in self.item_table:
            tmp = (self.item_table[key][1](self.item_table[key][0]))
            if tmp:
                detail.append(tmp)
        return "{} {}cr3: {} cpl: {} events: {}".format(
            self['events'][0], "".join(detail), self['vmexit']['cr3'],
            self['vmexit']['cpl'], self['events'])

    def repr_items(self, keys):
        for key in keys:
            if key in self:
                return "{}: {} ".format(key, self[key])
        return ""

    def repr_msr(self, keys):
        for key in keys:
            if key in self:
                return "{}: cmd={} val={} ".format(key,
                                                   msr_table[self[key]['cmd']],
                                                   self[key]['val'])


class AnalyzerSyscall(analyzer_transaction.Analyzer):
    def __init__(self, f, target_vcpu, target_bin,
                 cr3_filter=None, ignore_set={}):
        super(AnalyzerSyscall, self).__init__(f, target_vcpu)
        self.p_extract_filename = re.compile(" |\n")
        self.event_table = self.init_events()
        self.cr3_filter = cr3_filter
        self.ignore_events = self.create_ignore_set(ignore_set)
        self.systracs = []
        self.trac_enable = False
        self.target_bin = target_bin
        self.process_set = []
        self.shadow_process_set = []
        self.track_cr3 = False
        self.track_cr3_force = False
        self.save_cr3 = False
        self.tmp_preemp = False

    def init_events(self):
        event_table = {
            'set_cr3': [re.compile("cr_write 3"), self.extract_set_cr3],
            'syscall': [re.compile("kvm_linux_em_syscall"),
                        self.extract_syscall],
            'sysret': [re.compile("kvm_em_sysret"), self.extract_sysret],
            'execve': [re.compile("kvm_execve_filename"), self.handle_execve],
            'open': [re.compile("kvm_open_filename"), self.extract_open],
            'vmexit': [re.compile("kvm_exit_cr3"), self.handle_exit_cr3],
            'cpuid': [re.compile("kvm_cpuid"), self.extract_cpuid],
            'msr_read': [re.compile("msr_read"), self.extract_msr],
            'msr_write': [re.compile("msr_write"), self.extract_msr],
        }
        return event_table

    def create_ignore_set(self, ignore_set):
        ignore_events = []
        if ignore_set['nmi']:
            ignore_events.append("EXCEPTION_NMI")
        if ignore_set['cr_access']:
            ignore_events.append("CR_ACCESS")
        if ignore_set['apic']:
            ignore_events.append("kvm_apic")
        if ignore_set['io']:
            ignore_events.append("IO_INSTRUCTION")
            ignore_events.append("kvm_mmio")
            ignore_events.append("kvm_fast_mmio")
        if ignore_set['interrupt']:
            ignore_events.append("PENDING_INTERRUPT")
            ignore_events.append("EXTERNAL_INTERRUPT")
            ignore_events.append("PREEMPTION_TIMER")
        return ignore_events

    def check_ignored_event(self, events):
        if set(self.ignore_events) & set(events):
            return False
        return True

    def add_process_set(self, cr3):
        if self.tmp_preemp and not self.track_cr3_force:
            self.tmp_preemp = False
            self.track_cr3 = False
            return
        if cr3 not in self.process_set:
            self.process_set.append(cr3)
        if cr3 not in self.shadow_process_set:
            self.shadow_process_set.append(cr3)
            print("{}".format(self.shadow_process_set))
        self.track_cr3 = False
        self.track_cr3_force = False
        self.tmp_preemp = False

    def remove_process_set(self, cr3):
        self.process_set.remove(cr3)
        if not self.process_set:
            self.trac_enable = False

    def check_family_process(self, cr3):
        if cr3 in self.process_set:
            return True
        return False

    def behavior(self, exit_reason):
        transaction = transactions_syscall()
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

            for key in self.event_table:
                if self.event_table[key][0].search(s):
                    transaction[key] = self.event_table[key][1](s)
                    break

        if not self.trac_enable:
            return None, True

        if self.track_cr3 and "kvm_cr" in events:
            self.add_process_set(transaction['set_cr3'])

        if self.track_cr3 and "PREEMPTION_TIMER" in events:
            self.tmp_preemp = True

        if not self.check_family_process(transaction['vmexit']['cr3']):
            return None, True

        if ('syscall' in transaction and
           'sys_wait' in transaction['syscall']):
            transaction['events'] = events
            self.track_cr3 = True

        if ('syscall' in transaction and
           'sys_exit_group' in transaction['syscall']):
            self.remove_process_set(transaction['vmexit']['cr3'])

        if (self.cr3_filter and
           not transaction['vmexit']['cr3'] == self.cr3_filter):
            return None, True

        if not self.check_ignored_event(events):
            return None, True

        transaction['events'] = events

        return transaction, False

    def extract_set_cr3(self, s):
        ms = self.p_event.split(s)
        set_cr3 = ["set cr3", ms[2].split(" ")[17][:-1]]
        self.systracs.append(set_cr3)
        return set_cr3[1][2:]

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

    def handle_execve(self, s):
        filename = self.extract_execve(s)
        if self.target_bin in filename:
            self.track_cr3 = True
            self.track_cr3_force = True
            self.trac_enable = True
        return filename

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

    def extract_open(self, s):
        ms = self.p_event.split(s)
        if ms:
            ret_str = []
            filename = self.p_extract_filename.split(ms[2])[4:-2]
            for c in filename:
                ret_str.append(chr(int("0x{}".format(c), 16)))
            openfile = ["open", "".join(ret_str)]
            self.systracs.append(openfile)
            return openfile

    def extract_rax_value(self, s, sysret=False):
        ms = self.p_event.split(s)
        if ms:
            if sysret:
                rax_str = ms[2].split(" ")[8]
                rax_str = rax_str[:-1]
            else:
                rax_str = ms[2].split(" ")[1]
            return rax_str

    def handle_exit_cr3(self, s):
        cr3_data = self.extract_exit_cr3(s)
        return {'cr3': cr3_data[0], 'cpl': cr3_data[1][:-1]}

    def extract_exit_cr3(self, s):
        ms = self.p_event.split(s)
        if ms:
            components = ms[2].split(" ")
            return (components[10], components[12])

    def extract_cpuid(self, s):
        ms = self.p_event.split(s)
        if ms:
            value = ms[2].split(" ")[11:]
            return value[1]

    def extract_msr(self, s):
        ms = self.p_event.split(s)
        if ms:
            value = ms[2].split(" ")[13:]
            return {'cmd': value[1], 'val': value[3][:-1]}


def show_transactions(tracs):
    for t in tracs:
        print(repr(t))


def show_syscall_trace(tracs):
    for t in tracs:
        print(repr(t))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    ignore_set = {}
    parser.add_argument('filename', metavar='filename')
    parser.add_argument('target_vcpu', metavar='target vcpu')
    parser.add_argument('target_bin', metavar='target binary')
    parser.add_argument('--cr3', nargs='?', metavar='cr3 filtering')
    parser.add_argument('--syscall', action='store_true')
    parser.add_argument('--ignore_nmi', action='store_true')
    parser.add_argument('--ignore_cr_access', action='store_true')
    parser.add_argument('--ignore_apic', action='store_true')
    parser.add_argument('--ignore_io', action='store_true')
    parser.add_argument('--ignore_interrupt', action='store_true')
    args = parser.parse_args()
    ignore_set['nmi'] = args.ignore_nmi
    ignore_set['cr_access'] = args.ignore_cr_access
    ignore_set['apic'] = args.ignore_apic
    ignore_set['io'] = args.ignore_io
    ignore_set['interrupt'] = args.ignore_interrupt
    with open(args.filename) as f:
        a = AnalyzerSyscall(f, args.target_vcpu, args.target_bin,
                            cr3_filter=args.cr3,
                            ignore_set=ignore_set)
        a.create_transactions()
        show_transactions(a.tracs)
        if args.syscall:
            show_syscall_trace(a.systracs)
