__author__ = 'ling'

from cpuinfo import *

if CPU_64BITS:
    from linux_syscall64 import *
else:
    from linux_syscall32 import *

def write_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        length = arg2
        if arg2 > 0x10:
            length = 0x10
        data = dbg.read(arg1, length)
        print sys_name + ':'+hex(cur_pc)+':' + data + '###'

def read_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        data = dbg.read(arg1, arg2)
        print sys_name + ':'+hex(cur_pc)+':' + hex(arg0) +':' + hex(arg1) + ":" + hex(arg2)
        print sys_name + ':'+hex(cur_pc)+':' + data
        print hex(dbg.regs.rax)

def default_sys_call_handler(dbg, cur_pc, sys_name, arg0, arg1, arg2, isafter):
    if isafter:
        print sys_name + ':'+hex(cur_pc)+':' + hex(arg0) +':' + hex(arg1) + ":" + hex(arg2)


sys_call_handlers = {'write': write_handler, 'read': read_handler}

