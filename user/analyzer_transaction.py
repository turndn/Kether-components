#! /usr/bin/env python

import sys
import re


class Analyzer(object):
    def __init__(self, f, target_vcpu):
        self.f = f
        self.tracs = []
        self.p_kvm_exit = re.compile("kvm_exit:")
        self.p_kvm_exit_reason = re.compile("reason [\w\_]*")
        self.p_kvm_entry = re.compile("kvm_entry")
        self.p_event = re.compile(": ")
        self.vcpu = "[{}]".format(target_vcpu)

    def create_transactions(self):
        while True:
            s = self.f.readline()
            if not s:
                break
            if not self.is_target_vcpu(s):
                continue
            if self.is_kvm_exit(s):
                val, ignored = self.behavior(self.get_exit_reason(s))
                if not ignored:
                    self.tracs.append(val)

    def is_target_vcpu(self, s):
        if self.vcpu in s:
            return True
        return False

    def behavior(self, exit_reason):
        transaction = [exit_reason]
        while True:
            s = self.f.readline()
            if not s:
                break
            elif self.is_kvm_entry(s):
                break
            else:
                event = self.extract_event(s)
                transaction.append(event)
        return transaction, False

    def extract_event(self, s):
        ms = self.p_event.split(s)
        if ms:
            return ms[1]

        raise ValueError("Fix regular expression pattern for event")

    def is_kvm_exit(self, s):
        return self.p_kvm_exit.search(s)

    def get_exit_reason(self, s):
        ms = self.p_kvm_exit_reason.search(s)
        if ms:
            return ms.group(0)[7:]
        raise ValueError("Exit reason is not found.")

    def is_kvm_entry(self, s):
        return self.p_kvm_entry.search(s)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: {} [filename] [target vcpu]".format(sys.argv[0]))
        sys.exit(1)

    with open(sys.argv[1]) as f:
        a = Analyzer(f, sys.argv[2])
        a.create_transactions()
        reason = {'kvm_skip_emulated_instruction': [0, 0],
                  'kvm_emulate_insn': [0, 0]}
        for t in a.tracs:
            print(repr(t))
