#!/usr/bin/env python3

import socket
import struct
import time

class SOCKS5Tester:
    def __init__(self, host='localhost', port=1080):
        self.host = host
        self.port = port
    
    def connect(self):
        """Create a new connection to the SOCKS5 server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        return self.sock
    
    def send_handshake(self, version=0x05, nmethods=1, methods=[0x00]):
        """Send SOCKS5 handshake"""
        data = struct.pack('!BB', version, nmethods)
        for method in methods:
            data += struct.pack('!B', method)
        self.sock.send(data)
        return self.sock.recv(1024)
    
    def send_request(self, cmd=0x01, atyp=0x01, addr='127.0.0.1', port=80):
        """Send SOCKS5 request"""
        data = struct.pack('!BBBB', 0x05, cmd, 0x00, atyp)
        
        if atyp == 0x01:  # IPv4
            ip_parts = [int(x) for x in addr.split('.')]
            data += struct.pack('!BBBB', *ip_parts)
        elif atyp == 0x03:  # Domain
            data += struct.pack('!B', len(addr))
            data += addr.encode()
        
        data += struct.pack('!H', port)
        self.sock.send(data)
        return self.sock.recv(1024)
    
    def close(self):
        """Close the connection"""
        self.sock.close()
    
    def test_invalid_version(self):
        """Test invalid SOCKS version"""
        print("Testing invalid SOCKS version...")
        self.connect()
        response = self.send_handshake(version=0x04)
        print(f"Response: {response.hex()}")
        self.close()
        return response
    
    def test_no_methods(self):
        """Test no authentication methods"""
        print("Testing no authentication methods...")
        self.connect()
        response = self.send_handshake(nmethods=0)
        print(f"Response: {response.hex()}")
        self.close()
        return response
    
    def test_unsupported_auth(self):
        """Test unsupported authentication method"""
        print("Testing unsupported authentication method...")
        self.connect()
        response = self.send_handshake(methods=[0x02])  # Username/password
        print(f"Response: {response.hex()}")
        self.close()
        return response
    
    def test_unsupported_command(self):
        """Test unsupported command (BIND)"""
        print("Testing unsupported command (BIND)...")
        self.connect()
        self.send_handshake()
        response = self.send_request(cmd=0x02)  # BIND command
        print(f"Response: {response.hex()}")
        self.close()
        return response
    
    def test_unsupported_atyp(self):
        """Test unsupported address type"""
        print("Testing unsupported address type...")
        self.connect()
        self.send_handshake()
        response = self.send_request(atyp=0x02)  # Reserved address type
        print(f"Response: {response.hex()}")
        self.close()
        return response
    
    def test_connection_refused(self):
        """Test connection refused (port 1)"""
        print("Testing connection refused...")
        self.connect()
        self.send_handshake()
        response = self.send_request(port=1)  # Port 1 (usually not listening)
        print(f"Response: {response.hex()}")
        self.close()
        return response
    
    def test_large_domain(self):
        """Test very large domain name"""
        print("Testing large domain name...")
        large_domain = 'a' * 300  # Very long domain
        self.connect()
        self.send_handshake()
        response = self.send_request(atyp=0x03, addr=large_domain)
        print(f"Response: {response.hex()}")
        self.close()
        return response

def main():
    tester = SOCKS5Tester()
    
    print("=== Advanced SOCKS5 Error Testing ===")
    print()
    
    # Run all tests
    tests = [
        tester.test_invalid_version,
        tester.test_no_methods,
        tester.test_unsupported_auth,
        tester.test_unsupported_command,
        tester.test_unsupported_atyp,
        tester.test_connection_refused,
        tester.test_large_domain,
    ]
    
    for test in tests:
        try:
            test()
            print()
        except Exception as e:
            print(f"Test failed: {e}")
            print()
    
    print("=== Testing Complete ===")

if __name__ == "__main__":
    main() 