#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pysocks",
#     "requests",
# ]
# ///
import requests
import hashlib
import argparse
import configparser
import codecs
import os
import sys

class ZTESMS:
    def __init__(self, router_ip, password, proxy=None, username=None):
        self.router_ip = router_ip
        self.password = password
        self.username = username
        self.session = requests.Session()
        self.headers = {
            'Referer': f'http://{router_ip}/index.html',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.stok_cookie = None
        
        # Configure proxy if provided
        if proxy:
            proxy_type, proxy_addr, proxy_port = self._parse_proxy(proxy)
            
            # Configure the requests session to use the proxy
            proxy_dict = {}
            if proxy_type.lower() == 'socks4':
                proxy_dict = {
                    'http': f'socks4://{proxy_addr}:{proxy_port}',
                    'https': f'socks4://{proxy_addr}:{proxy_port}'
                }
            elif proxy_type.lower() == 'socks5':
                proxy_dict = {
                    'http': f'socks5://{proxy_addr}:{proxy_port}',
                    'https': f'socks5://{proxy_addr}:{proxy_port}'
                }
            elif proxy_type.lower() == 'http':
                proxy_dict = {
                    'http': f'http://{proxy_addr}:{proxy_port}',
                    'https': f'http://{proxy_addr}:{proxy_port}'
                }
            
            self.session.proxies.update(proxy_dict)
            print(f"Using {proxy_type} proxy: {proxy_addr}:{proxy_port}")

        # Initialize version info during object creation
        self.wa_inner_version, self.cr_version = self.get_version_info()

    def _parse_proxy(self, proxy_str):
        """Parse proxy string in format type:host:port"""
        try:
            parts = proxy_str.split(':')
            if len(parts) == 3:
                proxy_type, proxy_addr, proxy_port = parts
                return proxy_type, proxy_addr, proxy_port
            else:
                # Default to SOCKS5 if only host:port is provided
                proxy_addr, proxy_port = parts
                return "SOCKS5", proxy_addr, proxy_port
        except Exception as e:
            print(f"Invalid proxy format. Use 'type:host:port' or 'host:port'. Error: {e}")
            return None, None, None
        
    def _send_get_command(self, cmd, params=None):
        """Helper method to send GET commands to goform_get_cmd_process"""
        url = f'http://{self.router_ip}/goform/goform_get_cmd_process'
        default_params = {'isTest': 'false'}
        if isinstance(cmd, str):
            default_params['cmd'] = cmd
        if params:
            default_params.update(params)
            
        try:
            response = self.session.get(url, params=default_params, headers=self.headers)
            return response.json()
        except Exception as e:
            print(f"Error sending GET command: {e}")
            return None

    def _send_set_command(self, goformId, data=None, include_ad=True):
        """Helper method to send POST commands to goform_set_cmd_process"""
        url = f'http://{self.router_ip}/goform/goform_set_cmd_process'
        default_data = {
            'isTest': 'false',
            'goformId': goformId
        }
        
        # Add AD to default_data if needed (except for initial LOGIN without username)
        if include_ad and (self.username or goformId != 'LOGIN'):
            default_data['AD'] = self.calculate_ad()
        
        if data:
            default_data.update(data)
        
        try:
            response = self.session.post(url, data=default_data, headers=self.headers)
            return response.json()
        except Exception as e:
            print(f"Error sending SET command: {e}")
            return None

    def get_LD(self):
        """Get LD value from router - required for authentication"""
        result = self._send_get_command('LD')
        return result["LD"].upper() if result else ""

    def get_version_info(self):
        """Get wa_inner_version and cr_version from router"""
        params = {
            'cmd': 'cr_version,wa_inner_version',
            'multi_data': '1'
        }
        result = self._send_get_command(None, params)
        if result:
            wa_inner_version = result.get('wa_inner_version', '')
            cr_version = result.get('cr_version', '')
            print(f"Device version: {wa_inner_version}, cr_version: {cr_version}")
            return wa_inner_version, cr_version
        return '', ''

    def get_rd(self):
        """Get RD value from router"""
        result = self._send_get_command('RD')
        return result["RD"] if result else ''

    def hash_password(self, password, ld):
        """Hash password with LD value as required by ZTE routers"""
        # First hash the password with SHA-256
        initial_hash = hashlib.sha256(password.encode()).hexdigest().upper()
        # Then hash the combination of hashed password and LD value
        final_hash = hashlib.sha256((initial_hash + ld).encode()).hexdigest().upper()
        return final_hash

    def calculate_ad(self):
        """Calculate AD verification code required for goform_set_cmd_process calls
        
        The AD code is calculated by:
        1. Concatenating wa_inner_version and cr_version and hashing with MD5
        2. Getting the RD value from the router
        3. Concatenating the version hash with RD and hashing again with MD5
        """

        version_string = self.wa_inner_version + self.cr_version
        version_hash = hashlib.md5(version_string.encode()).hexdigest()
        
        # Get RD value from router which is used as a nonce
        router_rd = self.get_rd()
        
        # Calculate final AD verification code by hashing version_hash + RD
        combined_hash_input = version_hash + router_rd
        verification_code = hashlib.md5(combined_hash_input.encode()).hexdigest()
        
        return verification_code
    
    def encode_message(self, message):
        """Encode message to UCS2 (hex format)"""
        # Encode message to UTF-16BE and convert to hex
        utf16_bytes = message.encode('utf-16-be')
        hex_str = codecs.encode(utf16_bytes, 'hex').decode('ascii')
        return hex_str
    
    def login(self):
        """Login to the ZTE router web interface"""
        print("Logging in to router")
        
        # Get LD value for password hashing
        ld = self.get_LD()
        if not ld:
            print("Failed to get LD value, cannot login")
            return False
            
        # Hash the password with LD
        hashed_password = self.hash_password(self.password, ld)
        
        # Determine if we need to use the multi-user login method
        if self.username:
            # Multi-user login (newer ZTE routers)
            data = {
                'user': self.username,
                'password': hashed_password,
            }
            result = self._send_set_command('LOGIN_MULTI_USER', data)
        else:
            # Single-user login (older ZTE routers)
            data = {'password': hashed_password}
            result = self._send_set_command('LOGIN', data, include_ad=False)
        
        # Check for stok cookie
        stok = self.session.cookies.get('stok')
        if stok:
            print(f"Login successful, received stok: {stok}")
            return True
        else:
            print(f"Login failed: {result}")
            return False

    def send_sms(self, phone_number, message):
        """Send SMS through ZTE router"""
        if not self.login():
            return False
        
        data = {
            'notCallback': 'true',
            'Number': phone_number,
            'MessageBody': self.encode_message(message),
            'ID': '-1',
            'encode_type': 'UNICODE',
        }
        
        result = self._send_set_command('SEND_SMS', data)
        if result and result.get('result') == 'success':
            print(f"SMS sent successfully to {phone_number}")
            return True
        else:
            print(f"Failed to send SMS: {result}")
            return False
    
    def logout(self):
        """Logout from router"""
        result = self._send_set_command('LOGOUT')
        
        if result and result.get('result') == 'success':
            print("Logout successful")
            return True
        else:
            print(f"Logout failed: {result}")
            return False

def read_config():
    """Read configuration from config.ini file"""
    config = configparser.ConfigParser()
    
    # Check if config file exists, create default if not
    if not os.path.exists('config.ini'):
        config['DEFAULT'] = {
            'RouterIP': '192.168.254.1',
            'Password': 'your_password_here',
            'Proxy': ''  # Empty string means no proxy
        }
        
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        
        print("Created default config.ini file. Please edit with your actual router password.")
        sys.exit(1)
    
    config.read('config.ini')
    
    router_ip = config['DEFAULT']['RouterIP']
    password = config['DEFAULT']['Password']
    username = config['DEFAULT'].get('Username', '')  # Empty string by default
    proxy = config['DEFAULT'].get('Proxy', '')  # Get proxy if exists, otherwise empty string
    
    return router_ip, password, username, proxy

def main():
    parser = argparse.ArgumentParser(description='Send SMS via ZTE Router')
    parser.add_argument('--number', '-n', help='Phone number to send SMS to')
    parser.add_argument('--message', '-m', help='Message to send')
    parser.add_argument('--proxy', help='Proxy in format type:host:port (e.g. socks5:127.0.0.1:9050)')
    args = parser.parse_args()
    
    # If no arguments provided, ask interactively
    phone_number = args.number
    message = args.message
    
    if not phone_number:
        phone_number = input("Enter phone number: ")
    
    if not message:
        message = input("Enter message: ")
    
    # Read config
    router_ip, password, config_username, config_proxy = read_config()
    
    # Command line proxy overrides config file proxy
    proxy = args.proxy if args.proxy else config_proxy
    
    # Initialize ZTE SMS sender
    zte = ZTESMS(router_ip, password, proxy, config_username)
    
    # Send SMS
    success = zte.send_sms(phone_number, message)

    # Logout
    if success:
        zte.logout()

if __name__ == "__main__":
    main()
