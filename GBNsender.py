"""A Sender for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201

import argparse
import queue as que
import logging
import math
from scapy.sendrecv import send
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT
from collections import OrderedDict

FORMAT = "[SENDER:%(lineno)3s - %(funcName)10s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TIMEOUT = 1  # number of seconds before packets are retransmitted


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


class GBNSender(Automaton):
    """Sender implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Maximum window size of the sender
        n_bits: number of bits used to encode sequence number
        receiver: IP address of the receiver
        sender: IP address of the sender
        q: Queue for all payload messages
        buffer: buffer to save sent but not acknowledged segments
        current: Sequence number of next data packet to send
        unack: First unacked segment
        receiver_win: Current window advertised by receiver, initialized with
                      sender window size
        Q_3_2: Is Selective Repeat used?
        SACK: Is SACK used?
        Q_3_4: Is Congestion Control used?
    """

    def parse_args(self, sender, receiver, n_bits, payloads, win,
                   Q_3_2, Q_3_3, Q_3_4, **kwargs):
        """Initialize Automaton."""
        Automaton.parse_args(self, **kwargs)
        self.win = win
        self.n_bits = n_bits
        assert self.win < 2**self.n_bits
        self.receiver = receiver
        self.sender = sender
        self.q = que.Queue()
        for item in payloads:
            self.q.put(item)

        #Sender buffer
        self.buffer = OrderedDict()
        #The current packet of the SEND status.
        self.current = 0
        #The smallest packet waiting to be ack'ed
        self.unack = 0
        self.receiver_win = win
        self.Q_3_2 = Q_3_2
        self.SACK = Q_3_3
        self.Q_3_4 = Q_3_4
        self.retransmit_flag = False

        #Bonus
        if(self.Q_3_4):
            self.CWND_fp = 1.0
            self.CWND = math.floor(self.CWND_fp)
            self.ssthresh = math.inf
            self.CWND_data = list()
            self.CWND_data.append(self.CWND_fp)
            log.debug("Initialize CWND: %s. ", self.CWND_data)
        else:
            #No CWND, it is neutralized by setting equal to the sender window
            self.CWND = self.win
        self.effective_window = min(self.CWND,self.win,self.receiver_win)
        #header length 
        self.hlen = 6
        #to indicate if the retransmission is being done because of a timeout
        self.timeout_hanjing = False
        #to indicate if the retransmission is being done because of duplicate ACK packets
        self.dup_ack_hanjing = False
        #include a list to track duplicated acks 
        self.dup_ack = list()

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the receiver and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.receiver and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.SEND()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("All packets successfully transmitted!")

    @ATMT.state()
    def SEND(self):
        """Main state of sender.

        New packets are transmitted to the receiver as long as there is space
        in the window.
        """
        if(self.retransmit_flag):
            self.retransmit_flag = False
            raise self.RETRANSMIT()

        # check if you still can send new packets to the receiver
        if len(self.buffer) < self.effective_window:
            try:
                # get next payload (automatically removes it from queue)
                payload = self.q.get(block=False)
                log.debug("Sending packet num: %s", self.current)

                # add the current segment to the buffer
                self.buffer[self.current] = payload
                log.debug("Current buffer size: %s. Current buffer keys: %s", len(self.buffer), list(self.buffer.keys()))

                ###############################################################
                # create a GBN header with the correct header field values    #
                # send a packet to the receiver containing the created header #
                # and the corresponding payload                               #
                ###############################################################
                
                if(self.SACK == 0):
                    header_GBN = GBN(type = 'data', len = len(payload), hlen = 6, num = self.current, win = self.win)
                if(self.SACK == 1):
                    header_GBN = GBN(type = 'data', options = 1, len = len(payload), hlen = 6, num = self.current, win = self.win)
                
                send(IP(src = self.sender, dst = self.receiver) / header_GBN / payload)

                # sequence number of next packet
                self.current = int((self.current + 1) % 2**self.n_bits)

                # back to the beginning of the state
                # (send next packet if possible)
                raise self.SEND()

            # no more payload pieces in the queue --> if all are acknowledged,
            # we can end the sender
            except que.Empty:
                if self.unack == self.current:
                    raise self.END()

    @ATMT.receive_condition(SEND)
    def packet_in(self, pkt):
        """Transition: Packet coming in from the receiver"""
        raise self.ACK_IN(pkt)

    @ATMT.state()
    def ACK_IN(self, pkt):
        
        #This is a function that checks whether the received ACK is within the boundaries 
        """Receiver window is used instead of the effective window to take into account
        the very small effective window case after the timeout event. In this case we should 
        be able to receive ACKs that are larger than our window value"""
        def in_window(num):
            cond_1 = (self.unack + self.receiver_win) >= num >= self.unack
            cond_2 = ((self.unack + self.receiver_win) >= 2**self.n_bits) and (((self.unack + self.receiver_win) % 2**self.n_bits) >= num)           
            return (cond_1 or cond_2)
                
        """State for received ACK."""
        # check if type is ACK
        if pkt.getlayer(GBN).type == 0:
            log.error("Error: data type received instead of ACK %s", pkt)
            raise self.SEND()
        else:
            log.debug("Received ACK %s", pkt.getlayer(GBN).num)
            if(self.Q_3_4):
                if(self.CWND < self.ssthresh):
                    self.CWND_fp += 1.0
                    self.CWND = math.floor(self.CWND_fp)
                    self.effective_window = min(self.CWND,self.win,self.receiver_win)
                    self.CWND_data.append(self.CWND_fp)
                    log.debug("CWND log (from ACK_in): %s. ", self.CWND_data)
                else:
                    self.CWND_fp = self.CWND_fp + (1.0 / self.CWND)
                    self.CWND = math.floor(self.CWND_fp)
                    self.effective_window = min(self.CWND,self.win,self.receiver_win)
                    self.CWND_data.append(self.CWND_fp)
                    log.debug("CWND log (from ACK_in): %s. ", self.CWND_data)
            #Set the receiver window size to the received window value
            self.receiver_win = pkt.getlayer(GBN).win
            #Set the ack number to the received value
            ack = pkt.getlayer(GBN).num
            if(not in_window(ack)):
                log.error("Error: ACK received is out-of-window %s, discard!", pkt)
        #Create a sender buffer key list for easier manipulation
        Sender_buffer_keys = list(self.buffer.keys())
        
        #Detect the index of the key value that is ack'ed, and erase everything coming beforehand
        if ((ack-1)%2**self.n_bits) in Sender_buffer_keys:
            index = Sender_buffer_keys.index((ack-1)%2**self.n_bits)
            Sender_buffer_keys = Sender_buffer_keys[:index+1]
            log.debug("Packet numbers deleted from the sender buffer %s", Sender_buffer_keys)
            for i in Sender_buffer_keys:
                del self.buffer[i]
            log.debug("The new sender buffer %s", list(self.buffer.keys()))

        #New unack is the latest ack number
        self.unack = ack

        #Question 3.2, detect duplicate acks and go into the transmission state when necessary
        if(self.Q_3_2 or self.Q_3_4): 
            #implement a queue for checking duplicated ack
            self.dup_ack.append(ack)
            log.debug("duplicated ack buffer is %s", self.dup_ack)
            if(len(self.dup_ack) >= 3):
                if(self.dup_ack[-1] == self.dup_ack[-2] == self.dup_ack[-3]):
                    self.dup_ack.clear()
                    log.debug("Duplicate ACKs for sequence number %s", ack)
                    if(self.Q_3_2):
                        self.dup_ack_hanjing = True
                        self.retransmit_flag = True
                    if(self.Q_3_4):
                        self.ssthresh = self.CWND / 2
                        self.CWND_fp = self.ssthresh
                        self.CWND = math.floor(self.CWND_fp)
                        self.effective_window = min(self.CWND,self.win,self.receiver_win)
                        self.CWND_data.append(self.CWND_fp)
                        log.debug("CWND log: %s. ", self.CWND_data)
                    raise self.SEND()
        
        #Q3_3 optional field list construction
        if(self.SACK == 1 and (pkt.getlayer(GBN).options == 1) and (pkt.getlayer(GBN).hlen >6)):
            #Get the header length
            self.hlen = pkt.getlayer(GBN).hlen
            #Pull optional field parameters
            if(self.hlen >= 9):
                self.ledge1 = pkt.getlayer(GBN).ledge1
                self.len1 = pkt.getlayer(GBN).len1
            if(self.hlen >= 12):
                self.ledge2 = pkt.getlayer(GBN).ledge2
                self.len2 = pkt.getlayer(GBN).len2
            if(self.hlen == 15):
                self.ledge3 = pkt.getlayer(GBN).ledge3
                self.len3 = pkt.getlayer(GBN).len3
            self.retransmit_flag = True
            raise self.SEND()


        # back to SEND state
        raise self.SEND()

    @ATMT.timeout(SEND, TIMEOUT)
    def timeout_reached(self):
        """Transition: Timeout is reached for first unacknowledged packet."""
        log.debug("Timeout for sequence number %s", self.unack)
        #To indicate the retransmit state, it succeeds timeout state
        self.timeout_hanjing = True
        if(self.Q_3_4):
            self.ssthresh = self.CWND / 2
            self.CWND_fp = 1.0
            self.CWND = math.floor(self.CWND_fp)
            self.effective_window = min(self.CWND,self.win,self.receiver_win)
            self.CWND_data.append(self.CWND_fp)
            log.debug("CWND log (from timeout): %s. ", self.CWND_data)
        raise self.RETRANSMIT()

    @ATMT.state()
    def RETRANSMIT(self):
        """State for retransmitting packets."""

        ##############################################
        # retransmit all the unacknowledged packets  #
        # (all the packets currently in self.buffer) #
        ##############################################
        
        if(self.timeout_hanjing):
            #If we are coming from the timeout state, retransmit all the buffer
            for k,v in self.buffer.items():
                if(self.SACK == 0):
                    header_GBN = GBN(type = 'data', len = len(v), hlen = 6, num = k, win = self.win)
                else:
                    header_GBN = GBN(type = 'data', options = 1, len = len(v), hlen = 6, num = k, win = self.win)
                send(IP(src = self.sender, dst = self.receiver) / header_GBN / v)
                log.debug("Sending packet number: %s", k)
        
        if ((self.Q_3_2 == 1) and (self.dup_ack_hanjing == True) and (self.timeout_hanjing == False)):
            #just retransmit the packet that has been ack'ed 3 times consequtively
            header_GBN = GBN(type = 'data', len = len(self.buffer[self.unack]), hlen = 6, num = self.unack, win = self.win)
            send(IP(src = self.sender, dst = self.receiver) / header_GBN / self.buffer[self.unack])
            log.debug("Sending packet number: %s", self.unack)
        
        #Question 3.3
        if(self.SACK == 1 and (self.timeout_hanjing == False) and (self.hlen > 6)):
            if(self.hlen == 9):
                optionalHeader_list = list(range(self.ledge1, self.ledge1 + self.len1))          
            if(self.hlen == 12):
                optionalHeader_list = list(range(self.ledge1, self.ledge1 + self.len1)) + list(range(self.ledge2, self.ledge2 + self.len2))         
            if(self.hlen == 15):
                optionalHeader_list = list(range(self.ledge1, self.ledge1 + self.len1)) + list(range(self.ledge2, self.ledge2 + self.len2)) + list(range(self.ledge3, self.ledge3 + self.len3))          
            
            for i in optionalHeader_list:
                optionalHeader_list[optionalHeader_list.index(i)] = i % 2**self.n_bits
            
            #We need to find the difference between the sender buffer, and the optionalHeader_list
            Sender_buffer_keys = list(self.buffer.keys())           
            log.debug("The sender buffer: %s", Sender_buffer_keys)
            #Trimmed_sender_buffer includes the buffer list only up to the last packet number in the optional header list)
            trimmed_sender_buffer = Sender_buffer_keys[:Sender_buffer_keys.index(optionalHeader_list[-1])+1]
            #Retrans_list is the list of keys to be retransmitted
            log.debug("Trimmed Sender Buffer: %s", trimmed_sender_buffer)
            log.debug("Optional Header List: %s", optionalHeader_list)
            Retrans_list = [item for item in trimmed_sender_buffer if item not in optionalHeader_list]
            log.debug("SACK: packets should be retransmitted: %s", Retrans_list)
            for i in Retrans_list:
                header_GBN = GBN(type = 'data', options = 1 , len = len(self.buffer[i]), hlen = 6, num = i, win = self.win)
                send(IP(src = self.sender, dst = self.receiver) / header_GBN / self.buffer[i])
                log.debug("SACK Retransmission: Sending packet number: %s", i)
        # back to SEND state
        self.dup_ack_hanjing = False
        self.timeout_hanjing = False
        raise self.SEND()

if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN sender')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                             'number field')
    parser.add_argument('input_file', type=str,
                        help='Path to the input file')
    parser.add_argument('window_size', type=int,
                        help='The window size of the sender')
    parser.add_argument('Q_3_2', type=int,
                        help='Use Selective Repeat (question 3.2)')
    parser.add_argument('Q_3_3', type=int,
                        help='Use Selective Acknowledgments (question 3.3)')
    parser.add_argument('Q_3_4', type=int,
                        help='Use Congestion Control (question 3.4/Bonus)')

    args = parser.parse_args()

    bits = args.n_bits
    assert bits <= 8

    in_file = args.input_file
    # list for binary payload
    payload_to_send_bin = list()
    # chunk size of payload
    chunk_size = 2**6

    # fill payload list
    with open(in_file, "rb") as file_in:
        while True:
            chunk = file_in.read(chunk_size)
            if not chunk:
                break
            payload_to_send_bin.append(chunk)

    # initial setup of automaton
    GBN_sender = GBNSender(args.sender_IP, args.receiver_IP, bits,
                           payload_to_send_bin, args.window_size, args.Q_3_2,
                           args.Q_3_3, args.Q_3_4)

    # start automaton
    GBN_sender.run()
