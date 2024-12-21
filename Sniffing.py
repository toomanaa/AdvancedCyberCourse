import socket  # For creating and managing sockets
import struct  # For unpacking binary data into Python-readable formats
import binascii  # For converting binary data to ASCII representation

# Automatically detect the IP address of the host machine
host = socket.gethostbyname(socket.gethostname())
print(f"Monitoring host IP: {host}")

# Create a raw socket for sniffing network packets
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Bind the socket to the detected host IP on any port (port 0 indicates all ports)
s.bind((host, 0))

# Include IP headers in the captured packets
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable promiscuous mode to capture all packets on the network
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("Sniffing started... Press Ctrl+C to stop.")

while True:
    try:
        # Receive packets (maximum size set to 65565 bytes)
        packet = s.recvfrom(65565)

        # Extract the first 14 bytes of the Ethernet header
        ethernet_header = packet[0][0:14]
        eth_header = struct.unpack("!6s6s2s", ethernet_header)  # Unpack MAC addresses and EtherType

        # Convert the MAC addresses to human-readable hexadecimal format
        print("Destination MAC: %s Source MAC: %s Type: %s" % (
            binascii.hexlify(eth_header[0]),  # Destination MAC
            binascii.hexlify(eth_header[1]),  # Source MAC
            binascii.hexlify(eth_header[2])   # EtherType
        ))

        # Extract the next 20 bytes for the IP header
        ipheader = packet[0][14:34]
        ip_header = struct.unpack("!12s4s4s", ipheader)  # Extract source and destination IP addresses

        # Convert IP addresses from binary to human-readable format
        print("Source IP: %s Destination IP: %s" % (
            socket.inet_ntoa(ip_header[1]),  # Source IP
            socket.inet_ntoa(ip_header[2])   # Destination IP
        ))

    except KeyboardInterrupt:
        # Stop sniffing and disable promiscuous mode when Ctrl+C is pressed
        print("Sniffing stopped.")
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        exit()
