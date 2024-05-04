# Networkanalyzer

This Python script is designed to parse network packets from a hexdump file and extract various protocol headers and data from them. It supports parsing of Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, HTTP, and FTP protocols.

## Usage

1. Input: The input hexdump file should contain hexadecimal representations of network packets, with each packet separated by a blank line.
2. Output: The script parses each packet and prints out structured information about its headers and data.

## Structure

- `main()`: The main function of the script, responsible for orchestrating the parsing process.
- `read_hexdump(file_path)`: Reads the hexdump file and extracts individual frames (packets) as byte arrays.
- `process_frames(frames)`: Iterates over each frame, parses its Ethernet header, and delegates further parsing based on the Ethernet type.
- `parse_ethernet(frame)`: Parses the Ethernet header and determines the type of the payload (IPv4, IPv6, ARP).
- `parse_ipv4(packet)`: Parses the IPv4 header and extracts relevant fields like version, header length, source/destination IP, etc.
- `parse_ipv6(packet)`: Parses the IPv6 header and extracts fields including version, traffic class, flow label, source/destination IP, etc.
- `parse_arp(packet)`: Parses the ARP header and extracts fields such as hardware type, protocol type, sender/target MAC/IP addresses, etc.
- `parse_tcp(segment, src_ip, dst_ip, ip_payload_length)`: Parses the TCP header and extracts fields like source/destination ports, sequence numbers, flags, etc.
- `parse_udp(segment, src_ip, dst_ip, ip_payload_length, ip_version)`: Parses the UDP header and extracts fields including source/destination ports, length, checksum, etc.
- `parse_icmp(segment)`: Parses the ICMP header and extracts fields like type, code, checksum, etc.
- `parse_http(data)`: Parses HTTP packets and extracts information such as request/response type, method, status code, headers, etc.
- `parse_ftp(tcp_payload)`: Parses FTP packets and extracts commands/responses.
- `format_output(data)`: Formats the parsed data into a human-readable format for display.
- `calculate_checksum(data)`: Calculates the checksum of the given data using the Internet checksum algorithm.

## Dependencies

The script relies on the `socket`, `ipaddress`, and `binascii` modules for various networking operations and conversions.

## Execution

To run the script, ensure you have a hexdump file (`hexdmp.txt` by default) containing the network packets. Then execute the script using Python:

```bash
python packet_parser.py
```
