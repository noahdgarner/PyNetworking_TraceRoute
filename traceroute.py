#!/usr/bin/python


#Noah Garner
#10/31/2018
#Traceroute Project 2

#Sends ICMP echo requests instead of UDP packets. The TTL value / hop limit is used to determine the intermediate routers being traversed towards the destination. The router sends an ICMP Time Exceeded message back to the source.
#works a lot like NMAP

#I.E. a diagnostic tool for displaying the route and measuring transit deays of packets across an IP network.




import socket
import struct
import sys
import random


class flushfile(file):
    def __init__(self, f):
        self.f = f
    def write(self, x):
        self.f.write(x)
        self.f.flush()

sys.stdout = flushfile(sys.stdout)

def main(dest_name):
    dest_addr = dest_name
    port = random.randint(33434,33465)
    max_hops = 20
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        timeout = struct.pack("ll", 5, 0)
        


        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
        
        recv_socket.bind(("", port))
        sys.stdout.write(" %d  " % ttl)
        send_socket.sendto("", (dest_name, port))
        curr_addr = None
        curr_name = None
        finished = False
        tries = 1
        while not finished and tries > 0:
            try:
                _, curr_addr = recv_socket.recvfrom(512)
                finished = True
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error as (errno, errmsg):
                tries = tries - 1
                sys.stdout.write("* ")
        
        send_socket.close()
        recv_socket.close()
        
        if not finished:
            pass
        
        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = ""
        sys.stdout.write("%s\n" % (curr_host))

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break

if __name__ == "__main__":
	main(sys.argv[1])
