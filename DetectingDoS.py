import socket  # For creating raw sockets and handling network traffic
import struct  # For unpacking network packet headers
import time  # For managing time-based operations
import platform  # For detecting the operating system
import threading  # For running periodic dictionary updates in the background

# Function to periodically clear the IP address dictionary
def updates_dict():
    """
    This function clears the dictionary storing IP packet counts every 3 seconds.
    This helps avoid false positives from traffic that is no longer relevant.
    """
    while True:
        main.dict = {}  # Reset the dictionary
        print("Dictionary updated on ", time.ctime())  # Log the update time
        time.sleep(3)  # Wait for 3 seconds before the next reset
        if main.event.is_set():  # If the main thread signals to stop, break the loop
            break

# Main function for monitoring network traffic and detecting DDoS attacks
def main():
    # Detect the operating system and create a raw socket accordingly
    if platform.system() == "Windows":
        # Create a raw socket for Windows
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # Prompt the user for the IP address of the machine to monitor
        host = input("Enter the host that you would like to monitor: ")
        s.bind((host, 0))  # Bind the socket to the provided host IP
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers in captured packets
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode to capture all packets
    elif platform.system() == "Linux":
        # Create a raw socket for Linux
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # Captures all Ethernet packets

    # Start a background thread to periodically update the dictionary
    threading.Thread(target=updates_dict).start()

    # Initialize a shared event for clean shutdown and the IP tracking dictionary
    main.event = threading.Event()  # Shared event for thread synchronization
    main.dict = {}  # Dictionary to track IP packet counts
    No_of_IPs = 100  # Threshold: Number of packets from a single IP to trigger a DDoS alert

    # Begin monitoring network traffic
    while True:
        try:
            # Receive a packet from the network (maximum size is 65565 bytes)
            pkt = s.recvfrom(65565)

            # Extract the IP header (assuming Ethernet header is 14 bytes)
            ipheader = pkt[0][14:34]

            # Unpack the IP header fields (specific structure of the IP header)
            ip_hdr = struct.unpack("!8sB3s4s4s", ipheader)

            # Extract the source IP address and convert it to human-readable form
            IP = socket.inet_ntoa(ip_hdr[3])

            # Check if the IP address is already in the dictionary
            if IP in main.dict.keys():
                main.dict[IP] += 1  # Increment the packet count for this IP
                # If the packet count exceeds the threshold, log a potential DDoS alert
                if main.dict[IP] > No_of_IPs:
                    print(f"Large amount of traffic received from the IP address: {IP}")
            else:
                # If the IP address is new, add it to the dictionary with a count of 1
                main.dict[IP] = 1

        except KeyboardInterrupt:
            # Gracefully handle termination when the user presses Ctrl+C
            main.event.set()  # Signal the dictionary updater thread to stop
            exit()  # Exit the program

# Entry point for the program
if __name__ == "__main__":
    main()
