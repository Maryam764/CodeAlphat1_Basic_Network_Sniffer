#Here the libraries are being imported
import socket
import struct
HOST = "YOUR_WIFI_IP_ADDRESS"

# Created raw socket used socket in place of scapy library
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind((HOST, 0))
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
print("Network Sniffer Started...")
print("Press CTRL + C to stop\n")
try:
    while True:
        packet, address = sniffer.recvfrom(65535)

        # It will read ip header in this block
        ip_header = packet[0:20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        source_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        protocol = iph[6]
#if-else conditions used for protocols checking
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        print("Source IP:", source_ip)
        print("Destination IP:", dest_ip)
        print("Protocol:", protocol_name)
        print("-" * 35)

except KeyboardInterrupt:
    print("\nSniffer Stopped.")

finally:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sniffer.close()
