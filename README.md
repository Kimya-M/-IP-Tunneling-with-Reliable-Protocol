# IP Tunneling Simulator (Simple Silly VPN)

This project implements a simple IP Tunneling Simulator using Python and Scapy. It provides IP tunneling with reliability, ensuring that packets are sent and received in order. The reliability mechanism is achieved by adding a custom header containing sequence numbers and acknowledgment (ACK) fields.

## Features

- **IP Tunneling:** System A encapsulates IP packets inside another IP packet and forwards them to System B.
- **Reliability:** Ensures packets are received in the correct order and retransmits unacknowledged packets. Acknowledgments (ACK) are used to confirm successful receipt.
- **Multithreading:** Sending, receiving, ACK listening, and packet retransmission are handled on separate threads for both systems.
- **File Handling:** System A reads the input file (`salam.txt`), breaks it into 10-byte chunks, and sends each chunk as a packet. System A then writes the received data back to a file (`salami_dobare.txt`).

## How It Works

1. **System A:** Reads the input file (`salam.txt`) and breaks it into 10-byte chunks. Each chunk is used as the payload for a packet.
   - Encapsulates each payload inside an IP packet, encapsulates it again and forwards it to System B.
   
2. **System B:** Receives the encapsulated packets, acknowledges their receipt, and decapsulates the inner packet.
   - The decapsulated packet is forwarded back to System A after processing.

3. **Reliability:** System B sends ACKs for each received packet. If a packet is not acknowledged within a defined timeout period (`ACK_TIMEOUT`), System B will resend the packet.

4. **System A:** Receives the decapsulated packets, extracts the payload, and writes it to the output file (`salami_dobare.txt`).

## Setup

1. **IP Configuration:** Before running, make sure to set your system’s IP addresses in the configuration.
   
2. **Dependencies:** This project uses [Scapy](https://scapy.readthedocs.io/en/latest/) for packet manipulation. Install the required dependencies using:

   ```bash
   pip install scapy
   ```
   ## Running the Simulator

- Run the simulator on both systems with appropriate IP addresses configured.
- System A sends the packets, and System B acknowledges and forwards them back.

## Files

- `rely_on_me.py`: Contains a subclass for packet handling with sequence numbers and acknowledgment fields.
- `salam.txt`: The input file to be transmitted (split into 10-byte chunks).
- `salami_dobare.txt`: The output file where the received data is written.

## Multithreading

The program uses multithreading for:

- Sending packets from System A.
- Receiving packets at System B.
- Listening for ACKs and retransmitting unacknowledged packets.

## Acknowledgments

- [Scapy](https://scapy.readthedocs.io/en/latest/) for providing a powerful Python library for packet manipulation.
