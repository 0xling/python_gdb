__author__ = 'ling'

target = './test32'

from pygdb import *

'''
logger = logging.getLogger('pygdb')
logger.setLevel('ERROR')
'''

def simple_step(gdb):
    rip = gdb.regs.rip
    if rip&0xffff0000 == 0x08040000:
        print hex(rip)
    if rip == 0x08048473:
        gdb.kill()
    return 0

def enter_main(gdb):
    print "332211"
    gdb.single_step(True)
    gdb.set_event_handle(PTRACE_EVENT_SINGLE_STEP, simple_step)
    return 0

for i in range(2):
    print 'time:', i
    gdb = pygdb()
    gdb.load(target)
    print HEX(gdb.read(0x804844d, 8+4))
    gdb.bp_set(0x0804844d, handler=enter_main)
    gdb.run()
