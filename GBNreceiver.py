"""A Receiver for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201


import os
import random
import logging
import argparse
from scapy.sendrecv import send
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT

from operator import itemgetter
from itertools import groupby

from collections import OrderedDict
#from collections import OrderedDict

FORMAT = "   [RECEIVER:%(lineno)3s - %(funcName)12s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# fixed random seed to reproduce packet loss
random.seed('TEST')


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        options: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0),
                   #Conditional Field for the optional header
                   ConditionalField(ByteField("blen", 0), lambda pkt:pkt.hlen >= 9),
                   ConditionalField(ByteField("ledge1", 0), lambda pkt:pkt.hlen >= 9),
                   ConditionalField(ByteField("len1", 0), lambda pkt:pkt.hlen >= 9),
                   ConditionalField(ByteField("padding1", 0), lambda pkt:pkt.hlen >= 12),
                   ConditionalField(ByteField("ledge2", 0), lambda pkt:pkt.hlen >= 12),
                   ConditionalField(ByteField("len2", 0), lambda pkt:pkt.hlen >= 12),
                   ConditionalField(ByteField("padding2", 0), lambda pkt:pkt.hlen == 15),
                   ConditionalField(ByteField("ledge3", 0), lambda pkt:pkt.hlen == 15),
                   ConditionalField(ByteField("len3", 0), lambda pkt:pkt.hlen == 15)]


# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNReceiver(Automaton):
    """Receiver implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Window size advertised by receiver
        n_bits: number of bits used to encode sequence number
        p_data: loss probability for data segments (0 <= p_data < 1)
        p_ack: loss probability for ACKs (0 <= p_ack < 1)
        sender: IP address of the sender
        receiver: IP address of the receiver
        buffer: buffer to save received but out of sequence segments
        next: Next expected sequence number
        out_file: Name of output file
        p_file: Expected payload size
        end_receiver: Can we close the receiver?
        end_num: Sequence number of last packet + 1

    """

    def parse_args(self, receiver, sender, nbits, out_file, window, p_data,
                   p_ack, chunk_size, **kargs):
        """Initialize the automaton."""
        Automaton.parse_args(self, **kargs)
        self.win = window
        self.n_bits = nbits
        assert self.win <= 2**self.n_bits
        self.p_data = p_data
        assert p_data >= 0 and p_data < 1
        self.p_ack = p_ack
        assert p_ack >= 0 and p_ack < 1
        self.sender = sender
        self.receiver = receiver
        self.next = 0
        self.out_file = out_file
        self.p_size = chunk_size
        self.end_receiver = False
        self.end_num = -1

        #added buffer for out of order packets for 3.2
        self.buffer = OrderedDict()
        self.buffer_del = list()

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the sender and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.sender and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.WAIT_SEGMENT()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("Receiver closed")

    @ATMT.state()
    def WAIT_SEGMENT(self):
        """Waiting state for new packets."""
        log.debug("Waiting for segment %s", self.next)

    @ATMT.receive_condition(WAIT_SEGMENT)
    def packet_in(self, pkt):
        """Transition: Packet is coming in from the sender."""
        raise self.DATA_IN(pkt)

    @ATMT.state()
    def DATA_IN(self, pkt):
        """State for incoming data."""
        num = pkt.getlayer(GBN).num
        payload = bytes(pkt.getlayer(GBN).payload)


        def order_receiver_buffer(buffer_list, window, next, nbits):
            #let's see if we are in a wrap-up
            if(next + window < 2**nbits):
                #no wrap-up
                return sorted(buffer_list)
            else:
                buffer_list = sorted([x + (2**nbits) if x<next else x for x in buffer_list])
                return buffer_list

        # received segment was lost/corrupted in the network
        if random.random() < self.p_data:
            log.debug("Data segment lost: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)
            raise self.WAIT_SEGMENT()

        # segment was received correctly
        else:
            log.debug("Received: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)

            # check if segment is a data segment
            ptype = pkt.getlayer(GBN).type
            if ptype == 0:

                # check if last packet --> end receiver
                if len(payload) < self.p_size:
                    self.end_receiver = True
                    self.end_num = (num + 1) % 2**self.n_bits

                # this is the segment with the expected sequence number
                if num == self.next:
                    log.debug("Packet has expected sequence number: %s", num)

                    # append payload (as binary data) to output file
                    with open(self.out_file, 'ab') as file:
                        file.write(payload)

                    log.debug("Delivered packet to upper layer: %s", num)
                    
                    self.next = int((self.next + 1) % 2**self.n_bits)

                    iter = True
                    while iter:
                        self.buffer_del.clear()
                        iter = False
                        #Clear the buffer from used-to-be out-of-order, but now consecutive packets
                        for k,v in self.buffer.items():
                            if k == self.next:
                                with open(self.out_file, 'ab') as file:
                                    file.write(self.buffer[k])
                                self.buffer_del.append(k)
                                log.debug("Delivered packet to upper layer and removed %s in buffer.", k)
                                self.next = int((self.next + 1) % 2**self.n_bits)
                                iter = True
                        for i in self.buffer_del:
                            del self.buffer[i]

                # this was not the expected segment
                else:
                    log.debug("Out of sequence segment [num = %s] received. "
                              "Expected %s", num, self.next)
                    #solution for Q3.2 and Q3.3   
                    if ((len(self.buffer) < self.win) and (((self.next + self.win) > num > self.next) or (((self.next + self.win) >= 2**self.n_bits) and (((self.next + self.win) % 2**self.n_bits) >= num)))):
                        #Possibly, we may and can overwrite the buffer even if the packet has arrived for the second time
                        self.buffer[num] = payload    
                        log.debug("Out of sequence segment [num = %s] was added to the buffer. ", num)
                        log.debug("New receiver buffer is [num = %s]. ", self.buffer.keys())

                #solution for Q3.3
                #prepare the optional header field
                if(pkt.getlayer(GBN).options == 1):
                    buffer_list = list(self.buffer.keys()) 
                    buffer_list = order_receiver_buffer(buffer_list, self.win, self.next, self.n_bits)
                    log.debug("Receiver buffer to create Optional Header [num = %s]. ", buffer_list)
                    counter = 0
                    ledge1 = 0
                    len1 = 0
                    ledge2 = 0
                    len2 = 0
                    ledge3 = 0
                    len3 = 0
                    #If the list is empty, no optional field
                    if(buffer_list):
                        for k, subgroup in groupby(enumerate(buffer_list), lambda i: i[0]-i[1]):
                            if(counter == 0):
                                subgroup = list(map(itemgetter(1), subgroup))
                                ledge1 = subgroup[0]
                                len1 = len(subgroup)
                                counter += 1
                            elif(counter == 1):
                                subgroup = list(map(itemgetter(1), subgroup))
                                ledge2 = subgroup[0]
                                len2 = len(subgroup)
                                counter += 1
                            elif(counter == 2):
                                subgroup = list(map(itemgetter(1), subgroup))
                                ledge3 = subgroup[0]
                                len3 = len(subgroup)
                                counter += 1
            else:
                # we received an ACK while we are supposed to receive only
                # data segments
                log.error("ERROR: Received ACK segment: %s", pkt.show())
                raise self.WAIT_SEGMENT()

            # send ACK back to sender
            if random.random() < self.p_ack:
                # the ACK will be lost, discard it
                log.debug("Lost ACK: %s", self.next)

            # the ACK will be received correctly
            else:
                if(pkt.getlayer(GBN).options == 0):
                    header_GBN = GBN(type="ack",
                                    options=0,
                                    len=0,
                                    hlen=6,
                                    num=self.next,
                                    win=self.win)

                    log.debug("Sending ACK: %s", self.next)
                    send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                        verbose=0)
                elif(pkt.getlayer(GBN).options == 1):
                    blen = counter
                    if(counter == 0):
                        header_GBN = GBN(type="ack",
                                    options=1,
                                    len=0,
                                    hlen=6,
                                    num=self.next,
                                    win=self.win)
                        log.debug("Sending ACK: %s", self.next)
                        send(IP(src=self.receiver, dst=self.sender) / header_GBN, 
                            verbose=0)
                    if(counter == 1):
                        header_GBN = GBN(type="ack",
                                    options=1,
                                    len=0,
                                    hlen=9,
                                    blen=blen,
                                    ledge1=ledge1,
                                    len1=len1,
                                    num=self.next,
                                    win=self.win)
                        log.debug("Sending ACK: %s", self.next)
                        send(IP(src=self.receiver, dst=self.sender) / header_GBN, 
                            verbose=0)
                    if(counter == 2):
                        header_GBN = GBN(type="ack",
                                    options=1,
                                    len=0,
                                    hlen=12,
                                    blen=blen,
                                    ledge1=ledge1,
                                    len1=len1,
                                    ledge2=ledge2,
                                    len2=len2,
                                    num=self.next,
                                    win=self.win)
                        log.debug("Sending ACK: %s", self.next)
                        send(IP(src=self.receiver, dst=self.sender) / header_GBN, 
                            verbose=0)
                    if(counter == 3):
                        header_GBN = GBN(type="ack",
                                    options=1,
                                    len=0,
                                    hlen=15,
                                    blen=blen,
                                    ledge1=ledge1,
                                    len1=len1,
                                    ledge2=ledge2,
                                    len2=len2,
                                    ledge3=ledge3,
                                    len3=len3,
                                    num=self.next,
                                    win=self.win)
                        log.debug("Sending ACK: %s", self.next)
                        send(IP(src=self.receiver, dst=self.sender) / header_GBN, 
                            verbose=0)

                # last packet received and all ACKs successfully transmitted
                # --> close receiver
                if self.end_receiver and self.end_num == self.next:
                    raise self.END()

            # transition to WAIT_SEGMENT to receive next segment
            raise self.WAIT_SEGMENT()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN receiver')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                        'number field')
    parser.add_argument('output_file', type=str,
                        help='Path to the output file (data from sender is '
                        'stored in this file)')
    parser.add_argument('window_size', type=int,
                        help='The window size of the receiver')
    parser.add_argument('data_l', type=float,
                        help='The loss probability of a data segment '
                        '(between 0 and 1.0)')
    parser.add_argument('ack_l', type=float,
                        help='The loss probability of an ACK '
                        '(between 0 and 1.0)')

    args = parser.parse_args()
    output_file = args.output_file    # filename of output file
    size = 2**6                       # normal payload size
    bits = args.n_bits
    assert bits <= 8

    # delete previous output file (if it exists)
    if os.path.exists(output_file):
        os.remove(output_file)

    # initial setup of automaton
    GBN_receiver = GBNReceiver(args.receiver_IP, args.sender_IP, bits,
                               output_file, args.window_size, args.data_l,
                               args.ack_l, size)
    # start automaton
    GBN_receiver.run()
