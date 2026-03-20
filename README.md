# Python Deep Packet Inspection Engine

This is a complete Python port of the C++ DPI Engine, featuring single and multi-threaded packet processing, connection tracking, and rule-based dropping.

## Setup and Usage

Instead of CMake and Make, use standard python tools:

```bash
pip install -r requirements.txt
python app.py input.pcap output.pcap
```

### Advanced Examples

Block specific applications:
`python app.py input.pcap output.pcap --block-app YouTube --block-app TikTok`

Block a specific IP:
`python app.py input.pcap output.pcap --block-ip 192.168.1.50`

Block domain names containing a keyword:
`python app.py input.pcap output.pcap --block-domain facebook`

Multithreading configuration:
`python app.py input.pcap output.pcap --lbs 4 --fps 4`

To generate test data:
`python generate_test_pcap.py test_dpi.pcap`
