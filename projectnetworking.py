import binascii
import ipaddress
import socket
ETHERNET_TYPE_CODES = {
    '0800': 'IPv4',
    '0806': 'ARP',
    '86dd': 'IPv6',
    
}
def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = data[i] + (data[i+1] << 8)
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return ~checksum & 0xffff

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
    # Protocol numbers mapped to protocol names
    PROTOCOLS = {
        1: 'ICMP',    # Internet Control Message Protocol
        6: 'TCP',     # Transmission Control Protocol
        17: 'UDP',    # User Datagram Protocol
        2: 'IGMP',    # Internet Group Management Protocol #todo
    }

    ip = {}
    ip['Version'] = packet[0] >> 4
    ip['Header Length'] = (packet[0] & 0x0F) * 4
    ip['Total Length'] = int.from_bytes(packet[2:4], byteorder='big')
    ip['Identification'] = int.from_bytes(packet[4:6], byteorder='big')  # Decode Identification
    ip['TTL'] = packet[8]
    ip['Protocol Number'] = packet[9]
    ip['Protocol'] = PROTOCOLS.get(ip['Protocol Number'], f'Unknown ({ip["Protocol Number"]})')
    ip['Source IP'] = '.'.join(str(b) for b in packet[12:16])
    ip['Destination IP'] = '.'.join(str(b) for b in packet[16:20])
    return ip


def parse_ipv6(packet):
    NEXT_HEADER_PROTOCOLS = {
    0: 'Hop-by-Hop Options', #todo
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6', #todo
    #todo for all of this, don't know if they are necessary
    43: 'Routing Header',
    44: 'Fragment Header',
    59: 'No Next Header',
    60: 'Destination Options',
    50: 'ESP',
    51: 'AH',
}

    ipv6 = {}
    if len(packet) < 40:
        raise ValueError("Packet is too short to be a valid IPv6 packet")

    # Unpack the first 4 bytes to get version, traffic class, and flow label
    first_word = int.from_bytes(packet[0:4], byteorder='big')
    ipv6['Version'] = (first_word >> 28) & 0x0f
    if ipv6['Version'] != 6:
        raise ValueError("Invalid IP version, expected 6 for IPv6")

    ipv6['Traffic Class'] = (first_word >> 20) & 0xff
    ipv6['Flow Label'] = first_word & 0xfffff
    ipv6['Payload Length'] = int.from_bytes(packet[4:6], byteorder='big')

    # Handling Next Header using a dictionary to translate numbers to names
    next_header = packet[6]
    ipv6['Next Header'] = NEXT_HEADER_PROTOCOLS.get(next_header, f'Unknown ({next_header})')

    ipv6['Hop Limit'] = packet[7]

    # Handling IPv6 address formatting using ipaddress module
    ipv6['Source IP'] = str(ipaddress.ip_address(packet[8:24]))
    ipv6['Destination IP'] = str(ipaddress.ip_address(packet[24:40]))
    offset = 40  # Start of the payload after the header

    # Check for extension headers here and adjust the offset accordingly
    # This example does not parse the actual extension headers, just assumes their presence
    # based on the Next Header field. You might need to adjust this logic based on actual
    # extension header parsing needs.

    # A simple example, not accurate for all scenarios:
    extension_headers = [0, 43, 44, 60]  # Example header types that might be extensions
    while ipv6['Next Header'] in extension_headers:
        ext_hdr_length = packet[offset + 1]
        offset += (ext_hdr_length + 1) * 8  # Length of the extension header
        ipv6['Next Header'] = packet[offset]  # Update to the next header after parsing the current one

    return ipv6, offset



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


def parse_udp(segment, src_ip, dst_ip, ip_payload_length, ip_version):
    udp = {}
    header_length = 8  # UDP header is always 8 bytes long
    udp['Source Port'] = int.from_bytes(segment[0:2], byteorder='big')
    udp['Destination Port'] = int.from_bytes(segment[2:4], byteorder='big')
    udp['Length'] = int.from_bytes(segment[4:6], byteorder='big')
    udp['Checksum'] = segment[6:8].hex()

    # Determine the actual data length within the UDP segment
    actual_data_length = max(0, min(ip_payload_length, len(segment)) - header_length)
    udp['Data'] = segment[header_length:header_length + actual_data_length] if actual_data_length > 0 else b''

    # Construct the UDP pseudo-header and calculate the checksum
    if ip_version == 6:
        # For IPv6
        pseudo_header = socket.inet_pton(socket.AF_INET6, src_ip) + socket.inet_pton(socket.AF_INET6, dst_ip)
        pseudo_header += udp['Length'].to_bytes(2, byteorder='big') + (0).to_bytes(1, byteorder='big') + (17).to_bytes(1, byteorder='big')
    else:
        # For IPv4
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        pseudo_header = src_ip_bytes + dst_ip_bytes + b'\x00' + b'\x11' + udp['Length'].to_bytes(2, byteorder='big')

    checksum_data = pseudo_header + segment[:header_length + actual_data_length]
    if len(checksum_data) % 2 != 0:
        checksum_data += b'\x00'  # Padding to even length if necessary

    calculated_checksum = calculate_checksum(checksum_data)
    received_checksum = int.from_bytes(segment[6:8], byteorder='big')
    udp['Checksum Correct'] = (calculated_checksum == 0) and (received_checksum == 0 or calculated_checksum == received_checksum)

    # Additional handling for protocols like DNS
    if udp['Destination Port'] == 53 or udp['Source Port'] == 53:
        udp['DNS'] = parse_dns(segment[header_length:header_length + actual_data_length])

    return udp


def parse_dns(data):
    dns = {}
    dns['Transaction ID'] = int.from_bytes(data[0:2], 'big')
    flags = int.from_bytes(data[2:4], 'big')
    dns['Query/Response'] = 'Response' if flags & 0x8000 else 'Query'
    dns['Opcode'] = (flags & 0x7800) >> 11
    dns['Authoritative Answer'] = bool(flags & 0x0400)
    dns['Truncated'] = bool(flags & 0x0200)
    dns['Recursion Desired'] = bool(flags & 0x0100)
    dns['Recursion Available'] = bool(flags & 0x0080)
    dns['Response Code'] = flags & 0x000F
    dns['Questions'] = int.from_bytes(data[4:6], 'big')
    dns['Answer RRs'] = int.from_bytes(data[6:8], 'big')
    dns['Authority RRs'] = int.from_bytes(data[8:10], 'big')
    dns['Additional RRs'] = int.from_bytes(data[10:12], 'big')
    
    # Further parsing would be needed to decode the questions and answers sections
    
    return dns

def parse_tcp(segment, src_ip, dst_ip, ip_payload_length):
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

    # Construct the appropriate pseudo-header based on IP version
    if ':' in src_ip:  # IPv6
        pseudo_header = socket.inet_pton(socket.AF_INET6, src_ip)
        pseudo_header += socket.inet_pton(socket.AF_INET6, dst_ip)
        pseudo_header += ip_payload_length.to_bytes(4, byteorder='big')  # Length of the TCP segment
        pseudo_header += (6).to_bytes(1, byteorder='big') * 3  # Zero-padded next header (TCP is 6)
    else:  # IPv4
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        pseudo_header = src_ip_bytes + dst_ip_bytes + b'\x00' + b'\x06' + ip_payload_length.to_bytes(2, byteorder='big')

    checksum_data = pseudo_header + segment
    calculated_checksum = calculate_checksum(checksum_data)
    received_checksum = int.from_bytes(segment[16:18], byteorder='big')
    tcp['Checksum Correct'] = (calculated_checksum == received_checksum)

    # Calculate TCP Segment Length
    tcp_segment_length = ip_payload_length - tcp['Data Offset']
    tcp['Segment Length'] = tcp_segment_length

    # Next Sequence Number
    tcp['Next Sequence Number'] = tcp['Sequence Number'] + tcp_segment_length
    if tcp['Flags']['SYN'] or tcp['Flags']['FIN']:
        tcp['Next Sequence Number'] += 1  # SYN and FIN consume one sequence number

    # Parse TCP options if there are any
    if tcp['Data Offset'] > 20:
        tcp['Options'] = segment[20:tcp['Data Offset']]
    else:
        tcp['Options'] = None

    # Extracting TCP payload for potential application-layer parsing
    tcp_payload = segment[tcp['Data Offset']:]
    if tcp['Source Port'] == 80 or tcp['Destination Port'] == 80:
        tcp['HTTP'] = parse_http(tcp_payload)
    elif tcp['Destination Port'] == 21 or tcp['Source Port'] == 21:
        ftp_content = parse_ftp(tcp_payload)
        if ftp_content:
            tcp['FTP'] = ftp_content

    return tcp




def parse_icmp(segment):
    icmp = {}
    icmp['Type'] = segment[0]
    icmp['Code'] = segment[1]
    received_checksum = int.from_bytes(segment[2:4], byteorder='big')
    # Set the checksum field to zero for calculation
    checksum_data = segment[0:2] + b'\x00\x00' + segment[4:]
    calculated_checksum = calculate_checksum(checksum_data)
    icmp['Checksum'] = f"0x{received_checksum:04x}"
    # Verify the checksum
    icmp['Checksum Correct'] = (received_checksum == calculated_checksum)
    return icmp
def parse_http(data):
    try:
        http = {}
        # Convert bytes to string for easier processing
        content = data.decode('utf-8')
        lines = content.split('\r\n')
        
        # Check if the data starts with an HTTP method to identify it as a request
        if lines[0].startswith(tuple(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"])):
            parts = lines[0].split(' ')
            http['Type'] = 'Request'
            http['Method'] = parts[0]
            http['Path'] = parts[1]
            http['Version'] = parts[2]
        # Check for HTTP response
        elif lines[0].startswith("HTTP/"):
            parts = lines[0].split(' ')
            http['Type'] = 'Response'
            http['Version'] = parts[0]
            http['Status Code'] = parts[1]
            http['Status Message'] = ' '.join(parts[2:])
        
        # Extract headers into a dictionary
        http['Headers'] = {}
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                http['Headers'][key] = value
        return http
    except Exception as e:
        print(f"Error parsing HTTP: {e}")
        return None
def parse_ftp(tcp_payload):
    try:
        ftp = {}
        content = tcp_payload.decode('utf-8')  # Decode payload from bytes to string
        lines = content.split('\r\n')
        commands_responses = []
        for line in lines:
            if line:  # Avoid processing empty lines
                # FTP responses are typically three-digit numbers followed by space
                if line[0:3].isdigit() and line[3:4] == ' ':
                    commands_responses.append({'Response': line})
                else:
                    commands_responses.append({'Command': line})
        ftp['Activity'] = commands_responses
        return ftp
    except UnicodeDecodeError:
        return {'Error': 'Cannot decode FTP content'}


def process_frames(frames):
    processed_data = []
    for frame in frames:
        eth = parse_ethernet(frame)
        data = {"Ethernet": eth}
        if eth['Type'] == '0800':  # IPv4
            ip = parse_ipv4(frame[14:])
            ip_payload_length = ip['Total Length'] - ip['Header Length']
            data['IP'] = ip
            if ip['Protocol Number'] == 6:  # TCP
                tcp = parse_tcp(frame[14 + ip['Header Length']:], ip['Source IP'], ip['Destination IP'], ip_payload_length)
                data['TCP'] = tcp
                if tcp.get('HTTP'):
                    data['HTTP'] = tcp['HTTP']
            elif ip['Protocol Number'] == 17:  # UDP
                udp = parse_udp(frame[14 + ip['Header Length']:14 + ip['Total Length']], ip['Source IP'], ip['Destination IP'], ip_payload_length, 4)
                data['UDP'] = udp
            elif ip['Protocol Number'] == 1:  # ICMP
                icmp = parse_icmp(frame[14 + ip['Header Length']:14 + ip['Total Length']])
                data['ICMP'] = icmp
        elif eth['Type'] == '0806':  # ARP
            arp = parse_arp(frame[14:])
            data['ARP'] = arp
        elif eth['Type'] == '86DD':  # IPv6
            ipv6, payload_offset = parse_ipv6(frame[14:])
            data['IPv6'] = ipv6
            # Adjusting the offset for any potential extension headers
            if ipv6['Next Header'] == "TCP":  # TCP
                tcp = parse_tcp(frame[14 + payload_offset:], ipv6['Source IP'], ipv6['Destination IP'], ipv6['Payload Length'])
                data['TCP'] = tcp
                if tcp.get('HTTP'):
                    data['HTTP'] = tcp['HTTP']
            elif ipv6['Next Header'] == "UDP":  # UDP
                udp = parse_udp(frame[14 + payload_offset:], ipv6['Source IP'], ipv6['Destination IP'], ipv6['Payload Length'], 6)
                data['UDP'] = udp

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
            elif isinstance(value, dict) and (key == 'DNS' or key == 'HTTP'):
                output.append(f"  {key} Details:")
                for subkey, subvalue in value.items():
                    output.append(f"    {subkey}: {subvalue}")
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
