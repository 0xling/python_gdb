#!/usr/bin/python
#encoding:utf-8
__author__ = 'ling'

class hardware_breakpoint:
    '''
    Hardware breakpoint object.
    '''

    address     = None
    length      = None
    condition   = None
    description = None
    restore     = None
    slot        = None
    handler     = None

    ####################################################################################################################
    def __init__ (self, address=None, length=0, condition="", description="", restore=True, slot=None, handler=None):
        self.address     = address
        self.length      = length
        self.condition   = condition
        self.description = description
        self.restore     = restore
        self.slot        = slot
        self.handler     = handler
