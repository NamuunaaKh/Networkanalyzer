# How to Install and Run the Network Packet Parser

## Installation

1. **Clone the Repository**: Clone or download the repository containing the Network Packet Parser script to your local machine.

    ```bash
    git clone <repository_url>
    ```

2. **Navigate to the Directory**: Open a terminal or command prompt and navigate to the directory where you cloned the repository.

    ```bash
    cd network-packet-parser
    ```

## Running the Program

1. **Prepare Input Hexdump File**: Prepare a hexdump file containing hexadecimal representations of network packets. Each packet should be separated by a blank line.

2. **Run the Script**: Execute the `packet_parser.py` script using Python, providing the path to the input hexdump file as an argument.

    ```bash
    python packet_parser.py <path_to_hexdump_file>
    ```

    Example:

    ```bash
    python packet_parser.py hexdmp.txt
    ```

    If the hexdump file is located in a different directory, provide the full or relative path to the file.

3. **View Output**: The script will parse each packet in the hexdump file and print out structured information about its headers and data.

## Example Output

After running the script, you will see the parsed information for each packet displayed in the terminal. The output includes details such as Ethernet headers, IP headers (IPv4 or IPv6), TCP/UDP headers, ICMP headers, HTTP headers, FTP commands/responses, etc.
