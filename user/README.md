# Kether user components

```
usage: analyzer_syscall.py [-h] [--cr3 [cr3 filtering]] [--syscall]
                           [--ignore_nmi] [--ignore_cr_access] [--ignore_apic]
                           [--ignore_io] [--ignore_interrupt]
                           filename target vcpu target binary

positional arguments:
  filename
  target vcpu
  target binary

optional arguments:
  -h, --help            show this help message and exit
  --cr3 [cr3 filtering]
  --syscall
  --ignore_nmi
  --ignore_cr_access
  --ignore_apic
  --ignore_io
  --ignore_interrupt
```

You should prepare traces to use this program.
You can check [tracing][1] of KVM.

[1]: https://www.linux-kvm.org/page/Tracing
