import pandas as pd
import pyshark
from datetime import datetime

def extract_pcap_info(pcap_file, csv_output):
    # Read the pcap file using pyshark
    cap = pyshark.FileCapture(pcap_file)

    # Lists to store extracted data
    src_ips = []
    dst_ips = []
    src_ports = []
    dst_ports = []
    timestamps = []
    datas = []

    for packet in cap:
        # Check if the packet is IP and has a data layer
        if 'IP' in packet and hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            src_port = packet.tcp.srcport
            
            if src_port == '6379':
                src_ips.append(packet.ip.src)
                dst_ips.append(packet.ip.dst)
                src_ports.append(packet.tcp.srcport)
                dst_ports.append(packet.tcp.dstport)
                timestamp = datetime.utcfromtimestamp(float(packet.sniff_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                timestamps.append(timestamp)
                datas.append(packet.tcp.payload)


    # Create a DataFrame from the lists
    df = pd.DataFrame({
        'Source IP': src_ips,
        'Destination IP': dst_ips,
        'Source Port': src_ports,
        'Destination Port': dst_ports,
        "Timestamp": timestamps,
        'Data': datas
    })

    # Export the DataFrame to a CSV file
    df.to_csv(csv_output, index=False)



def main():
    # Example usage:
    extract_pcap_info(r'D:/Download/cartservice.pcapng', 'output.csv')

if __name__ == "__main__":
    main()
