import SocketServer
import requests
from time import sleep
import sys


class Handler(SocketServer.StreamRequestHandler):
    def handle(self):
        print 'connect from: %s:%s' % (self.client_address[0], self.client_address[1])
        while True:
            d = self.request.recv(1024)
            if d != '':
                print d
            else:
                print 'connect closed: %s:%s' % (self.client_address[0], self.client_address[1])
                break
            sleep(1)

port = None
try:
    port = sys.argv[1]
except:
    pass

if port is not None:
    server = SocketServer.ThreadingTCPServer(("0.0.0.0", int(port, 10)), Handler)
    server.serve_forever()
else:
    print 'usage:tcpserver port'
