# ZTE SMS

Sending SMS messages through ZTE routers and devices. 
Provides a Python script and a OpenWRT Lua 5.1 compatible Lua script.

Tested devices:
- ZTE 5G CPE MC7010

## Overview

This application allows you to send SMS messages via your ZTE device by simulating interactions with the device's web interface. ZTE routers and routers do not provide a standard API for sending SMS, so this application performs the necessary web requests to authenticate, calculate verification codes, and send messages.

This tool works with various ZTE devices that use similar web interfaces, including LTE routers, mobile hotspots, and USB modems. It should be compatible with a wide range of ZTE devices that feature SMS capabilities and a web management interface.
There are differences across ZTE devices so support would have to be added to the script to support older devices that use a non-hashed login.


## Features

- Login to ZTE router web interface
  - using the hashing method where device `wa_inner_version` and `cr_version` are used as "salt" for hashing
- Calculate verification codes (AD parameter) for `goform_set_cmd_process` calls
- Encode messages in the required format
  - Currently uses UNICODE which might not be supported on older ZTE devices
  - Unicode encoding supports emojis and all special characters
- Send a SMS message to specified phone number
- Log out from the router interface

## Requirements

### Python script

- Install `uv` from https://docs.astral.sh/uv/getting-started/installation/
- Run the script
- `uv` will handle installing the required dependencies

dependencies:
  - Python 3.10+
  - requests library
  - PySocks library (for SOCKS proxy support)

### Lua script

- Lua 5.1, tested on OpenWRT 23.05.5
  - `opkg update && opkg install lua-sha2 luasocket lua-cjson lua-md5 lua-argparse`


## Python script usage

1. Clone this repository or download the files.
3. Configure the application (see below).

### Configuration

Edit the `config.ini` file to set your router's IP address and web interface password:

```ini
[DEFAULT]
RouterIP = 192.168.254.1
Password = your_password_here
Proxy = 
; Example proxy formats:
; Proxy = socks5:127.0.0.1:11080
; Proxy = socks4:proxy.example.com:1080
; Proxy = http:10.10.1.10:8080
```

- **RouterIP**: Your ZTE device's IP address (default: 192.168.254.1)
- **Password**: The password for your device's web interface (do not encode)
- **Proxy**: Optional proxy settings for connecting to the device (empty by default)

## Usage

### Python Script Usage

Command line usage:
```bash
./zte-sms-sender.py --number "+123456789" --message "Hello, this is a test SMS!"
```

Or run without arguments for interactive prompts:
```bash
./zte-sms-sender.py
```

Using with SSH proxy:
1. Connect with SSH to your OpenWRT box and enable SSH's SOCKS proxy support on port 11080:
```bash
ssh -D 11080 root@openwrt-lan.somewhere
```

2. Use the SOCKS proxy to connect to your router for sending messages:
```bash
./zte-sms-sender.py --number "+123456789" --message "Hello, this is a test SMS!" --proxy "socks5:127.0.0.1:11080"
```

### As a Module

```python
from zte_sms import ZTESMS

# Initialize the ZTE SMS sender
zte = ZTESMS("192.168.254.1", "your_password_here")

# Or with proxy
# zte = ZTESMS("192.168.254.1", "your_password_here", "socks5:127.0.0.1:11080")

# Send SMS
zte.send_sms("+123456789", "Hello, this is a test SMS!")

# Always logout when done
zte.logout()
```

### How It Works

The application follows these steps to send an SMS:

1. **Login**: Authenticates with the device's web interface
2. **Version Info**: Retrieves the device's version information for AD calculation
3. **RD Value**: Gets the RD value from the device
4. **AD Calculation**: Calculates the AD verification code
5. **Message Encoding**: Encodes the message in UCS2 (hex) format
6. **SMS Sending**: Sends the SMS request with all required parameters
7. **Logout**: Logs out from the device

### Troubleshooting

- If login fails, verify your password and device IP address in `config.ini`
- The device may block access for 5 minutes after multiple failed attempts
- If using a proxy, make sure it's properly formatted and the proxy server is running

### Lua Script Usage (OpenWRT)

1. Install required packages:
```shell
opkg update
opkg install lua-sha2 luasocket lua-cjson lua-md5 lua-argparse
```

2. Copy the script to your OpenWRT device:

```shell
scp zte-sms-sender.lua root@openwrt:
```

Ensure the script is executable in OpenWRT
```shell
chmod +x zte-sms-sender.lua
```

3. Send SMS using command line:
```shell
./zte-sms-sender.lua --router 192.168.254.1 --password your_password_here --number "+123456789" --message "Hello from OpenWRT!"
```

Note: Make sure all required packages are installed before running the script. If you encounter any errors, verify that all dependencies were installed successfully.

## License

MIT