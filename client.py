import scapy.all as scapy 

def receive_and_relay():
    while True:

        packet = scapy.sniff(count=1, filter="ip", timeout=10)[0]

        if packet.haslayer(scapy.IP):
            inner_packet = packet[scapy.IP].payload
            if inner_packet.haslayer(scapy.IP):
                # Extract the inner packet
                inner_ip_packet = inner_packet[scapy.IP]
                inner_payload = inner_ip_packet.payload
                
                data = inner_payload
                inner_ip_packet.show()
                print(f"Received data: {data}")

                scapy.send(inner_ip_packet)

if __name__ == "__main__":
    receive_and_relay()
