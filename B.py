from scapy.all import sniff, send, IP, bind_layers, Raw
import threading
from queue import PriorityQueue
import time 
from rely_on_me import ReliableProtocol


bind_layers(IP, ReliableProtocol, proto=253)  # Use an unused protocol number like 253
bind_layers(ReliableProtocol, IP)

# Shared resources
packet_buffer = PriorityQueue()
buffer_lock = threading.Lock()


stop_threads = threading.Event()
#configuration 
SRC_IP = "192.168.43.222"
DEST_IP = "192.168.43.181"

# Function to send an acknowledgment
def send_ack(packet):
    seq_num = packet[ReliableProtocol].seq_num
    if seq_num !=1:
        ack_packet = IP(dst=packet[IP].src) / ReliableProtocol(seq_num=seq_num)
        send(ack_packet, verbose=0)
        print(f"ack sent for packet {seq_num}")

# Thread 1 - Packet Listener
def packet_listener():
    def packet_handler(packet):
        if packet.haslayer(ReliableProtocol):
            seq_num = packet[ReliableProtocol].seq_num 
            with buffer_lock:
                packet_buffer.put((seq_num, packet))
            send_ack(packet)

    sniff(filter=f"ip and src host {DEST_IP}", prn=packet_handler, store=False, stop_filter=lambda _: stop_threads.is_set())

# Thread 2 - Packet Processor
def packet_processor():
    while not stop_threads.is_set():
        try:
            with buffer_lock:
                if not packet_buffer.empty():
                    packet_id, packet = packet_buffer.get()
                    process_packet(packet_id, packet)
        except Exception as e:
            print(f"Error processing packet: {e}")

# Function to process a packet
def process_packet(packet_id, packet):
    time.sleep(0.1)
    print(f"Processing packet with ID: {packet_id}")
    #packet.show()
    inner_packet = packet[IP].payload
    real_inner_packet = packet[ReliableProtocol].payload
    if real_inner_packet.haslayer(IP):
        # Extract the inner packet
        inner_ip_packet = real_inner_packet[IP]
        inner_payload = inner_ip_packet.payload
        
        print(f"Received data: {inner_payload}")
        real_inner_packet.show()
        send(real_inner_packet)
        print("inner packet sent")

        

# Main function to start threads
def main():
    listener_thread = threading.Thread(target=packet_listener, daemon=True)
    processor_thread = threading.Thread(target=packet_processor, daemon=True)

    listener_thread.start()
    processor_thread.start()

    try:
        while True:
            pass  # Keep the main thread alive
    except KeyboardInterrupt:
        print("Shutting down threads...")
        stop_threads.set()

    listener_thread.join()
    processor_thread.join()
    print("All threads stopped.")

if __name__ == "__main__":
    main()
