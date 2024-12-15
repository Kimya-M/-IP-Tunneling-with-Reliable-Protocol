from scapy.all import sniff, send, IP
import threading
from queue import PriorityQueue
import time 
# Shared resources
packet_buffer = PriorityQueue()
buffer_lock = threading.Lock()

# Global flag to stop threads
stop_threads = threading.Event()
SRC_IP = "192.168.43.222"
DEST_IP = "192.168.43.181"

# Function to send an acknowledgment
def send_ack(packet):
    packet_id = packet[IP].id  # Use IP ID field
    ack_packet = IP(dst=packet[IP].src, id=packet_id) / b"ACK"
    send(ack_packet, verbose=0)

# Thread 1 - Packet Listener
def packet_listener():
    def packet_handler(packet):
        if packet.haslayer(IP):
            packet_id = packet[IP].id  # Use IP ID for ordering
            with buffer_lock:
                packet_buffer.put((packet_id, packet))
            #send_ack(packet)
            #print(f"ack for packet {packet_id} sent.")

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
    if inner_packet.haslayer(IP):
        # Extract the inner packet
        inner_ip_packet = inner_packet[IP]
        inner_payload = inner_ip_packet.payload
        
        print(f"Received data: {inner_payload}")
        inner_packet.show()
        send(inner_packet)
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
