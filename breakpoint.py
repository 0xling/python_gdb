#encoding:utf-8
__author__ = 'ling'

class breakpoint:
    address = None
    original_byte = None
    description = None
    restore = None
    handler = None

    def __init__(self, address=None, original_byte=None, description="", restore=True, handler=None):
        self.address = address
        self.original_byte = original_byte
        self.description = description
        self.restore = restore
        self.handler = handler
