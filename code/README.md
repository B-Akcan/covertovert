# Covert Storage Channel that exploits Protocol Field Manipulation using PSH Flag field in TCP
## How It Works
### Sender
For each bit of the message, we generate N packets with some of them having PSH flag set randomly.\
If the bit in the message is 1, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is odd.\
If the bit in the message is 0, among these N packets, we set PSH=1 such that total number of packets with PSH=1 is even.\
Then, we send these N packets and continue with the next bit of the message.

We calculate the start time as the time just after this function is called, end time as the time just after the last packet is sent.\
Transmission time is the difference between end time and start time. Transmission rate is binary message length divided by transmission time.
### Receiver
Due to the Scapy's working internals, sender sends 2 packets for each packet we send.\
For example, if sender sends 4 packets, the actual packets that we send are the 0th and 2nd packets. 1st and 3rd packets should be eliminated.\
That's why we use pkt_counter to check if the incoming packet is the actual packet.

For each incoming packet, we call process_packet() function. In it, we append the packet to packets array.\
If length of packets array is N, we count the total number of packets such that PSH=1.\
If total is even, receiver infers that the next message bit is 0 and appends that bit to bits string.\
If total is odd, receiver infers that the next message bit is 1 and appends that bit to bits string.\
Then we empty the packets array.\
When bits string size becomes 8, we convert bits string into a char, append that char to the message and empty the bits string.\
If the char is not ".", we continue sniffing packets. Else, we stop and write the message into log file.

## Parameters
### Sender
log_file_name: File that the message in string will be logged.\
min_msg_length: Minimum message length in number of characters.\
max_msg_length: Maximum message length in number of characters.\
N: The number of packets that we send for each bit of the message.
### Receiver
log_file_name: File that the message in string will be logged.\
N: The number of packets that we send for each bit of the message.

## Limitations
N should be bigger than 1. Otherwise there will be no encoding.\
Sender N and receiver N must be the same.\
min_msg_length must be greater than 0.\
max_msg_length must be greater than or equal to min_msg_length.

## Capacity
For min_msg_length=16 and max_msg_length=16:
* when N = 3, transmission rate = 4.04 bps
* when N = 4, transmission rate = 2.98 bps
* when N = 5, transmission rate = 2.33 bps
* when N = 6, transmission rate = 1.97 bps
* when N = 7, transmission rate = 1.69 bps
