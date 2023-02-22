import socket
# get all packets
# ETH_P_ALL = 0x03
# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

# to take apart bytes received
import struct
# ! for Big Endian
# types of unsigneds - 1. B - byte, 2. H = short (2 bytes), 3. I - int 4B, 4. Q - unsigned long 8B
# lowercase variants are signed versions
'''
data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
SOURCE, DEST, LEN, CHKSUM = struct.unpack("! H H H H", data[:8])
'''

'''
 ! identifying layers
 remember:
 1. Physical layer
 2. Data Link
 3. Network Layer
 4. Transport
 5. App
'''

# this will look at 2-4. Initially look at Ethernet frames then go to IPv4 packets and then TCP/UDP
# IPv6 support coming later
'''
 Ethernet frame:

 MAC Destination : 6B
 MAC Src: 6B
 Ethertype: 2B
 Payload: 46-1500B
 Frame check sum: 4B
'''
# RAW packets like the ones we get with the above command contain everything except the checksum
# payloads smaller than 46B are padded

def unpack_ethernet_frame(data):
    dest_mac, src_mac, ethertype = struct.unpack('! 6s 6s H', data[:14])
    return dest_mac, src_mac, ethertype, data[14:]

ETH_P_ALL = 0x03 # Listen for everything
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

while True:
    raw_data, addr = s.recvfrom(65565)
    dest_mac, src_mac, ethertype, payload = unpack_ethernet_frame(raw_data)
    print(f"[ Frame - Dest: {dest_mac}; Source: {src_mac}; EtherType: {hex(ethertype)} ]")

s.bind(("eth0", 0))

# Print basic socket info
print(s.getsockname())          # ('eth0', 3, 0, 1, b"\x08\x00'~\x88\x1f")

# Print all available interfaces
print(socket.if_nameindex())    # [(1, 'lo'), (2, 'eth0')]