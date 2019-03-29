#!/usr/bin/python
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = (sys.argv[1], int(sys.argv[2]))
print 'connecting to %s port %s' % server_address
sock.connect(server_address)

payloadObj = open(sys.argv[3],'rb').read()

payload=''
print 'sending payload...'
'''outf = open('payload.tmp','w')
outf.write(payload)
outf.close()'''
sock.send(payloadObj)

