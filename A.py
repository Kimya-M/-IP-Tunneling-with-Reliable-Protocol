from scapy.all import IP, send, sniff, Raw
import threading
import time
from queue import PriorityQueue


# Configuration
DEST_IP = "192.168.43.222"
INT_IP = "20.20.20.20"
SRC_IP = "192.168.43.181"
PACKET_INTERVAL = 0.1
ACK_TIMEOUT = 2
FILE_PATH1 = "salam.txt"
FILE_PATH2 = "salami_dobare.txt"
packet_buffer = PriorityQueue()

# Shared resources
pending_acks = {}  # Dictionary to track unacknowledged packets
ack_lock = threading.Lock()
stop_threads = threading.Event()


def send_packet(packet_id, chunk):
    inner_packet = IP(src=INT_IP, dst=SRC_IP, id=packet_id) / Raw(load=chunk)
    outer_packet = IP(src=SRC_IP, dst=DEST_IP, id=packet_id) / inner_packet
    send(outer_packet, verbose=0)
    print(f"Sent packet with ID: {packet_id}")

    # Add the packet to pending acks
    with ack_lock:
        pending_acks[packet_id] = time.time()

def send_ack(packet):
    packet_id = packet[IP].id  # Use IP ID field
    ack_packet = IP(dst=packet[IP].src, id=packet_id) / b"ACK"
    send(ack_packet, verbose=0)

# Thread 1 - Packet Listener
def packet_listener():
    def packet_handler(packet):
        if packet.haslayer(IP):
            packet_id = packet[IP].id  # Use IP ID for ordering

            packet_buffer.put((packet_id, packet))
            packet.show()
            #send_ack(packet)
            #print(f"ack for packet {packet_id} sent.")

    sniff(filter=f"ip and src host {INT_IP}", prn=packet_handler, store=False, stop_filter=lambda _: stop_threads.is_set())

def listen_for_acks():
    def ack_handler(packet):
        if packet.haslayer(IP):
            ack_id = packet[IP].id  # Use IP ID to identify ACK
            with ack_lock:
                if ack_id in pending_acks:
                    del pending_acks[ack_id]
                    print(f"Received ACK for packet ID: {ack_id}")

    sniff(filter=f"ip and src host {DEST_IP}", prn=ack_handler, stop_filter=lambda _: stop_threads.is_set(),
          store=False)


def resend_packets():
    while not stop_threads.is_set():
        time.sleep(1)
        current_time = time.time()
        with ack_lock:
            for packet_id, timestamp in list(pending_acks.items()):
                if current_time - timestamp > ACK_TIMEOUT:
                    print(f"Resending packet with ID: {packet_id}")


def packet_sender():
    """Continuously send packets."""
    with open(FILE_PATH1, 'r') as file:
        data = file.read()

    chunks = [data[i:i + 10] for i in range(0, len(data), 10)]

    for packet_id, chunk in enumerate(chunks):
        if stop_threads.is_set():
            break
        send_packet(packet_id, chunk)
        time.sleep(PACKET_INTERVAL)


if __name__ == "__main__":
    sender_thread = threading.Thread(target=packet_sender, daemon=True)
    #ack_listener_thread = threading.Thread(target=listen_for_acks, daemon=True)
    receiver_thread= threading.Thread(target=packet_listener, daemon=True)
    # resend_thread = threading.Thread(target=resend_packets, daemon=True)

    sender_thread.start()
    #ack_listener_thread.start()
    receiver_thread.start()
    # resend_thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping sender threads...")
        stop_threads.set()

    sender_thread.join()
    receiver_thread.join()

    print("Sender stopped.")
