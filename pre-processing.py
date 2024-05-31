from scapy.all import rdpcap
import os

def extract_pcap_data(pcap_file_path, output_file_path):
    # Read the pcap file
    packets = rdpcap(pcap_file_path)
    
    with open(output_file_path, 'w') as output_file:
        for packet in packets:
            try:
                # Extract the bytes of the packet
                packet_bytes = bytes(packet)
                # Get the length of the packet
                packet_length = len(packet_bytes)
                
                # Convert bytes to hex string
                packet_hex = ' '.join(f'{byte:02x}' for byte in packet_bytes)
                
                # Write the bytes and length to the output file
                output_file.write(f'{packet_hex}\t{packet_length}\n')
            except Exception as e:
                print(f"An error occurred while processing packet: {e}")

# Example usage
pcap_file_path = 'path/to/your/input.pcap'
output_file_path = 'path/to/your/output.txt'
extract_pcap_data(pcap_file_path, output_file_path)
