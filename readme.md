# BrainyDash

BrainyDash is a network monitoring and visualization tool that uses various Python libraries to display real-time information about network devices, services, and processes.

## Features

- **Real-time network monitoring**: Displays network usage, device status, and service information.
- **DHCP and DNS service monitoring**: Retrieves and displays DHCP and DNS service details.
- **Interactive console**: Uses the `rich` library to create a visually appealing and interactive console interface.

## Requirements

- Python 3.6+
- `platform`
- `subprocess`
- `sys`
- `psutil`
- `os`
- `dns.resolver`
- `rich`
- `yaml`
- `getchlib`
- `pythonping`
- `scapy`

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/brainydash.git
    cd brainydash
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Configuration

Create a `devices_services.yaml` file in the root directory with the following structure:

```yaml
devices:
  - name: "Device1"
    ip: "192.168.1.1"
  - name: "Device2"
    ip: "192.168.1.2"