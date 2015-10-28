__author__ = 'ling'

target = './test32'

from pygdb import *

gdb = pygdb()
gdb.load(target)

def enter_main(gdb):
    print "332211"
    return 0


print HEX(gdb.read_process_memory(0x0804844c, 8+4))
gdb.bp_set(0x0804844c, handler=enter_main)
print HEX(gdb.read_process_memory(0x0804844c, 8+4))
gdb.single_step(True)
def simple_step(gdb):
    print hex(gdb.regs.rip)
    return 0

gdb.set_event_handle(PTRACE_EVENT_SINGLE_STEP, simple_step)
gdb.run()

