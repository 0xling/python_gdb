__author__ = 'ling'

target = './test64'

from pygdb import *

gdb = pygdb()
gdb.load(target)

def enter_main(gdb):
    print "332211"
    print hex(gdb.regs.rip)
    print hex(gdb.regs.rax)
    print hex(gdb.regs.rsp)
    return 0


print HEX(gdb.read_process_memory(0x40057d, 32))

#gdb.write_process_memory(0x40057d, '\x12\x34\x56\x78\x90\x32\x54\x76\x87')
#print HEX(gdb.read_process_memory(0x40057d, 32))
#gdb.write_process_memory(0x40057d, '\xcc')
gdb.bp_set(0x40057D, handler=enter_main)

#print HEX(gdb.read_process_memory(0x400578+4, 32))
#print HEX(gdb.read_process_memory(0x40057d, 32))

f = open(target, 'rb')
print HEX(f.read()[0x57d:0x57d+32])
gdb.run()

