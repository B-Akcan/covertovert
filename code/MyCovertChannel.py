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

    def send(self, log_file_name, N):
        """
        N describes the number of packets that we send for each bit of the message.
        For each bit, we generate N packets with some of them having PSH flag set randomly.
        If the bit in the message is 1, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is not divisible by 2.
        If the bit in the message is 0, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is divisible by 2.
        """

        assert N > 1, "N should be bigger than 1"

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        # binary_message = self.convert_string_message_to_binary("a" * 3 + ".")

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
        ------------------------- DÖKÜMANTASYON YAZILACAK ----------------------------------
        """

        assert N > 1, "N should be bigger than 1"

        packets = sniff(filter="tcp",
                        prn=lambda pkt: self.process_packet(pkt, N),
                        stop_filter=self.check_stop)

        self.log_message(self.msg, log_file_name)
