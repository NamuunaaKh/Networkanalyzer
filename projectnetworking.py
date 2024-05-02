import binascii
ETHERNET_TYPE_CODES = {
    '0800': 'IPv4',
    '0806': 'ARP',
    '86dd': 'IPv6',
    '8100': 'VLAN-tagged frame (IEEE 802.1Q)',
    '8863': 'PPPoE Discovery Stage',
    '8864': 'PPPoE Session Stage'
}

def read_hexdump(file_path):
    frames = []
    current_frame = []
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() == "":
                if current_frame:
                    frames.append(b''.join(binascii.unhexlify(byte) for byte in current_frame))
                    current_frame = []
                continue
            parts = line.strip().split()
            if parts:
                current_frame.extend(parts[1:])
        if current_frame:
            frames.append(b''.join(binascii.unhexlify(byte) for byte in current_frame))
    return frames

def parse_ethernet(frame):
    eth = {}
    eth['Destination MAC'] = ':'.join(f"{b:02x}" for b in frame[0:6])
    eth['Source MAC'] = ':'.join(f"{b:02x}" for b in frame[6:12])
    eth_type_code = frame[12:14].hex()
    eth['Type'] = eth_type_code.upper()  # Standardize the type code format
    eth['Protocol'] = ETHERNET_TYPE_CODES.get(eth_type_code, 'Unknown')

    return eth


    
def parse_ipv4(packet):
    ip = {}
    ip['Version'] = packet[0] >> 4
    ip['Header Length'] = (packet[0] & 0x0F) * 4
    ip['Total Length'] = int.from_bytes(packet[2:4], byteorder='big')
    ip['TTL'] = packet[8]
    ip['Protocol'] = packet[9]
    ip['Source IP'] = '.'.join(str(b) for b in packet[12:16])
    ip['Destination IP'] = '.'.join(str(b) for b in packet[16:20])
    return ip
def parse_ipv6(packet):
    ipv6 = {}
    # Unpack the first 4 bytes to get version, traffic class, and flow label
    first_word = int.from_bytes(packet[0:4], byteorder='big')
    ipv6['Version'] = (first_word >> 28) & 0x0f
    ipv6['Traffic Class'] = (first_word >> 20) & 0xff
    ipv6['Flow Label'] = first_word & 0xfffff
    ipv6['Payload Length'] = int.from_bytes(packet[4:6], byteorder='big')
    ipv6['Next Header'] = packet[6]  # Similar to 'protocol' in IPv4
    ipv6['Hop Limit'] = packet[7]
    ipv6['Source IP'] = ':'.join(format(x, '02x') for x in packet[8:24]).upper()
    ipv6['Destination IP'] = ':'.join(format(x, '02x') for x in packet[24:40]).upper()

    return ipv6

def parse_arp(packet):
    arp = {}
    arp['Hardware Type'] = int.from_bytes(packet[0:2], byteorder='big')
    arp['Protocol Type'] = packet[2:4].hex()
    arp['Hardware Size'] = packet[4]
    arp['Protocol Size'] = packet[5]
    arp['Operation'] = int.from_bytes(packet[6:8], byteorder='big')
    arp['Sender MAC Address'] = ':'.join(f"{b:02x}" for b in packet[8:14])
    arp['Sender IP Address'] = '.'.join(str(b) for b in packet[14:18])
    arp['Target MAC Address'] = ':'.join(f"{b:02x}" for b in packet[18:24])
    arp['Target IP Address'] = '.'.join(str(b) for b in packet[24:28])
    return arp


def parse_udp(segment, ip_payload_length):
    udp = {}
    header_length = 8  # UDP header is always 8 bytes long
    udp['Source Port'] = int.from_bytes(segment[0:2], byteorder='big')
    udp['Destination Port'] = int.from_bytes(segment[2:4], byteorder='big')
    udp['Length'] = int.from_bytes(segment[4:6], byteorder='big')
    udp['Checksum'] = segment[6:8].hex()

    # Calculate payload; it's the part of the segment beyond the UDP header
    payload_length = udp['Length'] - header_length
    if payload_length > 0 and len(segment) >= header_length + payload_length:
        udp['Payload'] = str(int(len(segment[header_length:header_length + payload_length].hex())/2)) + ' bytes'
    else:
        udp['Payload'] = None


    return udp


def parse_tcp(segment, ip_payload_length):
    tcp = {}
    tcp['Source Port'] = int.from_bytes(segment[0:2], byteorder='big')
    tcp['Destination Port'] = int.from_bytes(segment[2:4], byteorder='big')
    tcp['Sequence Number'] = int.from_bytes(segment[4:8], byteorder='big')
    tcp['Acknowledgment Number'] = int.from_bytes(segment[8:12], byteorder='big')
    tcp['Data Offset'] = (segment[12] >> 4) * 4  # TCP header length in bytes
    tcp['Flags'] = {
        'URG': (segment[13] & 0x20) >> 5,
        'ACK': (segment[13] & 0x10) >> 4,
        'PSH': (segment[13] & 0x08) >> 3,
        'RST': (segment[13] & 0x04) >> 2,
        'SYN': (segment[13] & 0x02) >> 1,
        'FIN': segment[13] & 0x01
    }
    tcp['Window Size'] = int.from_bytes(segment[14:16], byteorder='big')
    tcp['Checksum'] = segment[16:18].hex()
    tcp['Urgent Pointer'] = int.from_bytes(segment[18:20], byteorder='big') if tcp['Flags']['URG'] else None

    # Calculate TCP Segment Length (IP payload length - TCP header length)
    tcp_segment_length = ip_payload_length - tcp['Data Offset']
    tcp['Segment Length'] = tcp_segment_length

    # Next Sequence Number
    tcp['Next Sequence Number'] = tcp['Sequence Number'] + tcp_segment_length
    if tcp['Flags']['SYN'] or tcp['Flags']['FIN']:
        tcp['Next Sequence Number'] += 1  # SYN and FIN consume one sequence number

    # Parse TCP options if there are any (indicated by a header length > 20 bytes)
    if tcp['Data Offset'] > 20:
        tcp['Options'] = segment[20:tcp['Data Offset']].hex()
    else:
        tcp['Options'] = None

    return tcp

def parse_icmp(segment):
    icmp = {}
    icmp['Type'] = segment[0]
    icmp['Code'] = segment[1]
    icmp['Checksum'] =segment[2:4].hex()
    return icmp
def process_frames(frames):
    processed_data = []
    for frame in frames:
        eth = parse_ethernet(frame)
        data = {"Ethernet": eth}
        if eth['Type'] == '0800':  # IP
            ip = parse_ipv4(frame[14:])
            ip_payload_length = ip['Total Length'] - ip['Header Length']
            data['IP'] = ip
            if ip['Protocol'] == 6:  # TCP
                tcp = parse_tcp(frame[14 + ip['Header Length']:], ip_payload_length)
                data['TCP'] = tcp
            elif ip['Protocol'] == 17:  # UDP
                udp = parse_udp(frame[14 + ip['Header Length']:14 + ip['Total Length']], ip_payload_length)
                data['UDP'] = udp
            elif ip['Protocol'] == 1:  # ICMP:
                icmp = parse_icmp(frame[14 + ip['Header Length']:14 + ip['Total Length']])
                data['ICMP'] = icmp
        elif eth['Type'] == '0806':  # ARP
            arp = parse_arp(frame[14:])
            data['ARP'] = arp
        elif eth['Type'] == '86dd':  # IPv6
            ipv6 = parse_ipv6(frame[14:])
            data['IPv6'] = ipv6
            
        processed_data.append(data)
    return processed_data







def format_output(data):
    output = []
    for protocol, fields in data.items():
        output.append(f"{protocol} Header:")
        for key, value in fields.items():
            if isinstance(value, dict) and key == 'Flags':
                output.append(f"  {key}:")
                for flag, flag_value in value.items():
                    output.append(f"    {flag}: {flag_value}")
            elif isinstance(value, dict):
                output.append(f"  {key}:")
                for subkey, subvalue in value.items():
                    output.append(f"    {subkey}: {subvalue}")
            else:
                output.append(f"  {key}: {value}")
    return "\n".join(output)




def main():
    file_path = 'hexdmp.txt'
    frames = read_hexdump(file_path)
    processed_data = process_frames(frames)
    for data in processed_data:
        print(format_output(data))
        print("\n" + "-"*40 + "\n")

if __name__ == "__main__":
    main()
