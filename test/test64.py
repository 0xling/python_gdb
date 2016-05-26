#!/usr/bin/python2 -u
__author__ = 'ling'

target = './test64'

from pygdb import *

gdb = pygdb()
#gdb.redir_stdout('127.0.0.1', 8889)
gdb.load(target)

def enter_main(gdb):
    print "332211"
    print hex(gdb.regs.rip)
    print hex(gdb.regs.rax)
    print hex(gdb.regs.rsp)
    sys.stderr.write('11111111111')
    sys.stdout.flush()
    return 0


print HEX(gdb.read(0x40057d, 32))

#gdb.write_process_memory(0x40057d, '\x12\x34\x56\x78\x90\x32\x54\x76\x87')
#print HEX(gdb.read_process_memory(0x40057d, 32))
#gdb.write_process_memory(0x40057d, '\xcc')
gdb.bp_set(0x40057D, handler=enter_main)

#print HEX(gdb.read_process_memory(0x400578+4, 32))
#print HEX(gdb.read_process_memory(0x40057d, 32))

f = open(target, 'rb')
print HEX(f.read()[0x57d:0x57d+32])
gdb.run()

