
# NetSniff (Network intrusion detection system)

NetSniff (Network intrusion detection system) is a real-time network packet sniffer and analyzer built using C. It supports signature-based detection, anomaly detection, and stateful protocol analysis to enhance network security. The tool captures and logs packets, detects potential threats, and sends alerts based on predefined signatures and traffic patterns.

## Features

- **Packet Sniffing**: Capture live network packets.
- **Signature-Based Detection**: Identify packets with specific malicious signatures.
- **Anomaly Detection**: Monitor and detect unusual traffic patterns.
- **Stateful Protocol Analysis**: Track and analyze TCP connections.
- **Logging**: Log packet details in JSON format for further analysis.
- **Alerting**: Send alerts for detected threats and anomalies.

## Dependencies

- `libpcap`: Packet capture library.
- `jansson`: JSON library for logging.
- `pthread`: POSIX thread library.

## Installation

1. **Install Dependencies**
   ```sh
   sudo apt-get install libpcap-dev libjansson-dev libmicrohttpd-dev
   ```

2. **Clone the Repository**
   ```sh
   git clone https://github.com/evildevill/NetSniff.git
   cd NetSniff
   ```

3. **Build the Project**
   ```sh
    gcc -o NetSniff NetSniff.c -lpcap -ljansson -lmicrohttpd -pthread
   ```

## Usage

1. **Run the Packet Sniffer**
   ```sh
   sudo ./NetSniff
   ```

   The application requires root privileges to capture network packets.

## Code Overview

### Main Components

- **Packet Handler**
  - Captures and processes each packet.
  - Extracts and prints packet details (timestamp, Ethernet header, IP header, payload).
  - Performs signature-based detection, anomaly detection, and stateful analysis.
  - Logs packet details in JSON format.
  - Sends alerts for detected signatures or anomalies.

- **Signature-Based Detection**
  - Checks packet payloads for specific malicious signatures.
  - Sends alerts when a signature match is found.

- **Anomaly Detection**
  - Monitors packet count over time.
  - Sends alerts when traffic volume exceeds a defined threshold.

- **Stateful Protocol Analysis**
  - Tracks TCP connections.
  - Sends alerts for new connections and when connection limit is exceeded.

### Functions

- **print_timestamp**: Prints the timestamp of the packet.
- **print_ethernet_header**: Prints the Ethernet header details.
- **print_payload**: Prints the packet payload in hex format.
- **log_packet_details**: Logs packet details in JSON format.
- **send_alert**: Sends alerts by writing messages to a file.
- **check_signature**: Checks for specific signatures in the packet payload.
- **check_anomalies**: Monitors packet counts to detect anomalies.
- **check_stateful_analysis**: Tracks TCP connections and detects stateful protocol anomalies.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License.

---

Happy Sniffing! 🕵️‍♂️

## Author

- [evildevill](https://github.com/evildevill)
