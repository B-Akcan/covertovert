from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
import random
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    pkt_counter = 0
    stop = False
    packets = []
    N_counter = 0
    bit_counter = 0
    bits = ""
    msg = ""

    def __init__(self):
        """
        - You can edit __init__.
        """
        pass

    def send(self, log_file_name, min_msg_length, max_msg_length, N):
        """
        N describes the number of packets that we send for each bit of the message.
        Sender N and receiver N must be the same.

        For each bit of the message, we generate N packets with some of them having PSH flag set randomly.
        If the bit in the message is 1, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is odd.
        If the bit in the message is 0, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is even.
        Then, we send these N packets and continue with the next bit of the message.
        
        We calculate the start time as the time just after this function is called, end time as the time just after the last packet is sent.
        Transmission time is the difference between end time and start time. Transmission rate is binary message length divided by transmission time.
        """

        start_time = time.time()

        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_msg_length, max_msg_length)

        for bit in binary_message:
            packets = []
            num = 0

            for _ in range(N - 1):
                rand_int = random.randint(0, 1)
                if rand_int == 1:
                    packet = IP(dst="receiver") / TCP(flags="P")
                    packets.append(packet)
                    num += 1
                else:
                    packet = IP(dst="receiver") / TCP(flags="")
                    packets.append(packet)
            
            if bit == "1":
                if num % 2 == 0:
                    packet = IP(dst="receiver") / TCP(flags="P")
                    packets.append(packet)
                else:
                    packet = IP(dst="receiver") / TCP(flags="")
                    packets.append(packet)
            else:
                if num % 2 == 0:
                    packet = IP(dst="receiver") / TCP(flags="")
                    packets.append(packet)
                else:
                    packet = IP(dst="receiver") / TCP(flags="P")
                    packets.append(packet)

            for packet in packets:
                super().send(packet)

        end_time = time.time()
        transmission_time = end_time - start_time
        bps = len(binary_message) / transmission_time
        print(f"Transmission time: {bps:.2f} bps")

    def process_packet(self, pkt, N):
        if self.pkt_counter % 2 == 0:
            self.packets.append(pkt)

            self.N_counter += 1
            if self.N_counter == N:
                self.N_counter = 0

                num = 0
                for packet in self.packets:
                    if packet[TCP].flags & 0x08:
                        num += 1
                self.packets = []
                
                bit = '0' if num % 2 == 0 else '1'
                self.bits += bit

                if len(self.bits) == 8:
                    char = self.convert_eight_bits_to_character(self.bits)
                    self.msg += char
                    self.bits = ""

                    if char == ".":
                        self.stop = True

        self.pkt_counter += 1
            
    def check_stop(self, packet):
        return self.stop

    def receive(self, log_file_name, N):
        """
        N describes the number of packets that we receive for each bit of the message.
        Sender N and receiver N must be the same.

        Due to the Scapy's working internals, sender sends 2 packets for each packet we send.
        For example, if sender sends 4 packets, the actual packets that we send are the 0th and 2nd packets. 1st and 3rd packets should be eliminated.
        That's why we use pkt_counter to check if the incoming packet is the actual packet.

        For each incoming packet, we call process_packet() function. In it, we append the packet to packets array.
        If length of packets array is N, we count the total number of packets such that PSH=1.
        If total is even, receiver infers that the next message bit is 0 and appends that bit to bits string.
        If total is odd, receiver infers that the next message bit is 1 and appends that bit to bits string.
        Then we empty the packets array.
        When bits string size becomes 8, we convert bits string into a char, append that char to the message and empty the bits string.
        If the char is not ".", we continue sniffing packets. Else, we stop and write the message into log file.
        """

        packets = sniff(filter="tcp",
                        prn=lambda pkt: self.process_packet(pkt, N),
                        stop_filter=self.check_stop)

        self.log_message(self.msg, log_file_name)
