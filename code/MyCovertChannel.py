from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
import random

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, N):
        """
        N describes the number of packets that we send for each bit of the message.
        For each bit, we generate N packets with some of them having PSH flag set randomly.
        If the bit in the message is 1, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is not divisible by 1.
        If the bit in the message is 0, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is divisible by 1.
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        for bit in binary_message:
            packets = []

            for i in range(N - 1):
                rand_int = random.randint(0, 1)
                if rand_int:
                    packet = IP(dst="receiver") / TCP(flags="P")
                    packets.append((1, packet))
                else:
                    packet = IP(dst="receiver") / TCP(flags="")
                    packets.append((0, packet))
                
            num = 0
            for packet in packets:
                num += packet[0]
            
            if bit:
                if num % 2 == 0:
                    packet = IP(dst="receiver") / TCP(flags="P")
                    packets.append((1, packet))
                else:
                    packet = IP(dst="receiver") / TCP(flags="")
                    packets.append((0, packet))
            else:
                if num % 2 == 0:
                    packet = IP(dst="receiver") / TCP(flags="")
                    packets.append((0, packet))
                else:
                    packet = IP(dst="receiver") / TCP(flags="P")
                    packets.append((1, packet))

            for packet in packets:
                send(packet[1])


    def receive(self, log_file_name, N):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """

        msg = ""

        while True:
            packets = sniff(filter="tcp and host sender", count=N)

            num = 0
            for packet in packets:
                if packet[TCP].flags & 0x08:
                    num += 1
            
            msg += str(num % 2)
            
        decoded_msg = ""

        for i in range(len(msg)-8):
            char = self.convert_eight_bits_to_character(msg[i:i+8])
            decoded_msg += char
            i += 8

        self.log_message(decoded_msg, log_file_name)
