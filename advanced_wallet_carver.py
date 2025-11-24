#!/usr/bin/env python3
"""
Advanced Bitcoin Wallet Carving Tool
Enhanced recovery techniques for heavily damaged or formatted drives
"""

import os
import sys
import struct
import hashlib
import binascii
import base58
from typing import List, Dict, Optional, Tuple
import math
from collections import defaultdict

class AdvancedWalletCarver:
    """
    Advanced carving techniques for wallet.dat recovery
    """
    
    def __init__(self, disk_image_path: str):
        self.disk_image_path = disk_image_path
        self.target_address = "147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL"
        
        # Decode target address to get the hash160
        self.target_hash160 = self.decode_address_to_hash160(self.target_address)
        
        # Extended Berkeley DB signatures with context
        self.berkeley_contexts = [
            # Complete wallet header patterns from 2011
            {
                'pattern': b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x62\x31\x05\x00'
                          b'\x09\x00\x00\x00\x00\x20\x00\x00',
                'name': 'Complete 2011 wallet header v9',
                'confidence': 0.95
            },
            {
                'pattern': b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x62\x31\x05\x00'
                          b'\x09\x00\x00\x00\x00\x10\x00\x00',
                'name': 'Complete 2011 wallet header v9 (4KB pages)',
                'confidence': 0.95
            },
            # Partial patterns with lower confidence
            {
                'pattern': b'\x62\x31\x05\x00\x09\x00\x00\x00',
                'name': 'Berkeley DB v9 signature',
                'confidence': 0.7
            },
            {
                'pattern': b'\x00\x05\x31\x62',
                'name': 'Berkeley DB magic (big-endian)',
                'confidence': 0.6
            }
        ]
        
        # Key patterns specific to 2011 wallets
        self.key_patterns_2011 = [
            # Unencrypted private key patterns from 2011
            {
                'prefix': b'\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20',
                'length': 32,
                'name': '2011 unencrypted private key (ASN.1)',
                'encrypted': False
            },
            {
                'prefix': b'\x30\x82\x01\x13\x02\x01\x01\x04\x20',
                'length': 32,
                'name': '2011 unencrypted private key (ASN.1 variant)',
                'encrypted': False
            },
            # Raw key patterns (sometimes keys are stored without ASN.1 wrapper)
            {
                'prefix': b'',  # No prefix, raw 32 bytes
                'length': 32,
                'name': 'Raw private key (context-based detection)',
                'encrypted': False,
                'requires_context': True
            }
        ]
        
        # Context strings that often appear near keys/addresses
        self.context_markers = [
            b'name',
            b'key!',
            b'key\x21',
            b'defaultkey',
            b'pool',
            b'"1',  # Often precedes addresses
            b'147',  # Start of our target address
        ]
    
    def decode_address_to_hash160(self, address: str) -> bytes:
        """
        Decode a Bitcoin address to its HASH160 representation
        """
        try:
            # Decode base58
            decoded = base58.b58decode_check(address)
            # Remove version byte (first byte)
            return decoded[1:]
        except:
            return b''
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        High entropy suggests encrypted/compressed data
        Low entropy suggests patterns or structure
        """
        if not data:
            return 0
        
        # Count byte frequencies
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in freq.values():
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)
        
        return entropy
    
    def find_address_patterns(self, data: bytes, offset: int = 0) -> List[Dict]:
        """
        Search for Bitcoin address patterns in data
        """
        findings = []
        
        # Search for our target address directly
        pos = 0
        while True:
            pos = data.find(self.target_address.encode(), pos)
            if pos == -1:
                break
            
            findings.append({
                'offset': offset + pos,
                'type': 'TARGET_ADDRESS_FOUND',
                'data': self.target_address,
                'confidence': 1.0
            })
            
            print(f"\n{'='*60}")
            print(f"!!! TARGET ADDRESS FOUND AT OFFSET 0x{offset + pos:X} !!!")
            print(f"{'='*60}\n")
            
            pos += 1
        
        # Search for HASH160 of target address
        if self.target_hash160:
            pos = 0
            while True:
                pos = data.find(self.target_hash160, pos)
                if pos == -1:
                    break
                
                findings.append({
                    'offset': offset + pos,
                    'type': 'TARGET_HASH160_FOUND',
                    'data': binascii.hexlify(self.target_hash160).decode(),
                    'confidence': 0.9
                })
                
                print(f"Found target address HASH160 at offset 0x{offset + pos:X}")
                
                pos += 1
        
        # Search for Bitcoin address pattern (starts with 1, length 26-35)
        # Using regex would be better but keeping it simple
        for i in range(len(data) - 35):
            if data[i] == ord('1'):
                # Check if it looks like a base58 address
                potential_addr = data[i:i+35]
                if self.is_likely_bitcoin_address(potential_addr):
                    addr_str = potential_addr.decode('ascii', errors='ignore').split()[0]
                    if len(addr_str) >= 26 and len(addr_str) <= 35:
                        findings.append({
                            'offset': offset + i,
                            'type': 'BITCOIN_ADDRESS',
                            'data': addr_str,
                            'confidence': 0.6
                        })
        
        return findings
    
    def is_likely_bitcoin_address(self, data: bytes) -> bool:
        """
        Quick check if data looks like a Bitcoin address
        """
        valid_chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        
        # Check first 26 characters
        for i in range(min(26, len(data))):
            if data[i] not in valid_chars:
                return False
        
        return True
    
    def extract_private_keys_advanced(self, data: bytes, offset: int) -> List[Dict]:
        """
        Advanced private key extraction with context analysis
        """
        keys = []
        
        # Method 1: Look for ASN.1 structures
        for pattern_info in self.key_patterns_2011:
            if pattern_info.get('requires_context'):
                continue
                
            prefix = pattern_info['prefix']
            if not prefix:
                continue
            
            pos = 0
            while pos < len(data) - len(prefix) - 32:
                found = data.find(prefix, pos)
                if found == -1:
                    break
                
                # Extract potential key
                key_start = found + len(prefix)
                key_data = data[key_start:key_start + 32]
                
                # Validate key (not all zeros, reasonable entropy)
                if self.validate_private_key(key_data):
                    keys.append({
                        'offset': offset + found,
                        'key_hex': binascii.hexlify(key_data).decode(),
                        'pattern': pattern_info['name'],
                        'confidence': 0.8
                    })
                
                pos = found + 1
        
        # Method 2: Context-based extraction
        # Look for 32-byte sequences near context markers
        for marker in self.context_markers:
            pos = 0
            while pos < len(data) - len(marker) - 32:
                found = data.find(marker, pos)
                if found == -1:
                    break
                
                # Check bytes after the marker
                for offset_after in [1, 2, 3, 4, 5, 10, 20]:
                    if found + len(marker) + offset_after + 32 <= len(data):
                        potential_key = data[found + len(marker) + offset_after:
                                            found + len(marker) + offset_after + 32]
                        
                        if self.validate_private_key(potential_key):
                            keys.append({
                                'offset': offset + found + len(marker) + offset_after,
                                'key_hex': binascii.hexlify(potential_key).decode(),
                                'pattern': f'Context-based near {marker.decode("ascii", errors="ignore")}',
                                'confidence': 0.5
                            })
                
                pos = found + 1
        
        # Method 3: Entropy-based detection
        # Look for 32-byte sequences with appropriate entropy
        for i in range(0, len(data) - 32, 4):  # Check every 4 bytes
            potential_key = data[i:i+32]
            entropy = self.calculate_entropy(potential_key)
            
            # Private keys typically have entropy between 7.5 and 8.0
            if 7.5 <= entropy <= 8.0:
                if self.validate_private_key(potential_key):
                    # Check if there's a context marker nearby
                    context_found = False
                    for marker in self.context_markers:
                        if marker in data[max(0, i-100):i+132]:
                            context_found = True
                            break
                    
                    if context_found:
                        keys.append({
                            'offset': offset + i,
                            'key_hex': binascii.hexlify(potential_key).decode(),
                            'pattern': f'Entropy-based (entropy={entropy:.2f})',
                            'confidence': 0.3
                        })
        
        return keys
    
    def validate_private_key(self, key_data: bytes) -> bool:
        """
        Validate if data could be a valid Bitcoin private key
        """
        if len(key_data) != 32:
            return False
        
        # Check if all zeros or all ones
        if all(b == 0 for b in key_data) or all(b == 0xFF for b in key_data):
            return False
        
        # Check if it's within the valid range for secp256k1
        # Max valid private key: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        max_key = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6af48A03BBFD25E8CD0364140')
        
        if key_data >= max_key:
            return False
        
        # Check minimum entropy (not too repetitive)
        if len(set(key_data)) < 8:  # At least 8 different bytes
            return False
        
        return True
    
    def derive_address_from_private_key(self, private_key_hex: str) -> str:
        """
        Derive Bitcoin address from private key
        """
        try:
            # Convert hex to bytes
            private_key = bytes.fromhex(private_key_hex)
            
            # Generate public key (simplified - would need proper secp256k1 implementation)
            # This is a placeholder - you'd need to use a proper library like ecdsa
            
            # For now, return empty string
            # In production, you'd use: ecdsa, bitcoin, or cryptography library
            return ""
        except:
            return ""
    
    def scan_with_sliding_window(self, chunk_size: int = 10485760):
        """
        Scan disk image using sliding window approach
        """
        print(f"\nScanning disk image: {self.disk_image_path}")
        print(f"Target address: {self.target_address}")
        print(f"Target HASH160: {binascii.hexlify(self.target_hash160).decode()}\n")
        
        file_size = os.path.getsize(self.disk_image_path)
        print(f"Disk size: {file_size:,} bytes ({file_size/(1024**3):.2f} GB)\n")
        
        all_findings = {
            'berkeley_db': [],
            'addresses': [],
            'private_keys': []
        }
        
        with open(self.disk_image_path, 'rb') as f:
            offset = 0
            
            while offset < file_size:
                # Read chunk
                f.seek(offset)
                chunk = f.read(chunk_size)
                
                if not chunk:
                    break
                
                # Progress
                progress = (offset / file_size) * 100
                print(f"\rScanning: {progress:.1f}% (offset 0x{offset:X})", end='')
                
                # Search for Berkeley DB signatures
                for ctx in self.berkeley_contexts:
                    pos = chunk.find(ctx['pattern'])
                    if pos != -1:
                        finding = {
                            'offset': offset + pos,
                            'type': ctx['name'],
                            'confidence': ctx['confidence']
                        }
                        all_findings['berkeley_db'].append(finding)
                        print(f"\nFound: {ctx['name']} at 0x{offset + pos:X}")
                
                # Search for addresses
                addr_findings = self.find_address_patterns(chunk, offset)
                all_findings['addresses'].extend(addr_findings)
                
                # Extract private keys
                key_findings = self.extract_private_keys_advanced(chunk, offset)
                all_findings['private_keys'].extend(key_findings)
                
                # Move window (with overlap to catch patterns on boundaries)
                offset += chunk_size - 1024  # 1KB overlap
        
        print("\n\nScan complete!")
        return all_findings
    
    def generate_detailed_report(self, findings: Dict, output_dir: str = "./recovery_output"):
        """
        Generate detailed forensic report
        """
        os.makedirs(output_dir, exist_ok=True)
        
        report_path = os.path.join(output_dir, "advanced_recovery_report.txt")
        
        with open(report_path, 'w') as f:
            f.write("="*80 + "\n")
            f.write("ADVANCED BITCOIN WALLET RECOVERY REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Disk Image: {self.disk_image_path}\n")
            f.write(f"Target Address: {self.target_address}\n")
            f.write(f"Target HASH160: {binascii.hexlify(self.target_hash160).decode()}\n\n")
            
            # Berkeley DB findings
            f.write("BERKELEY DB SIGNATURES FOUND:\n")
            f.write("-"*40 + "\n")
            for finding in findings['berkeley_db']:
                f.write(f"Offset: 0x{finding['offset']:X}\n")
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Confidence: {finding['confidence']:.2f}\n\n")
            
            # Address findings
            f.write("\nBITCOIN ADDRESSES FOUND:\n")
            f.write("-"*40 + "\n")
            
            # Prioritize target address findings
            target_findings = [f for f in findings['addresses'] if 'TARGET' in f['type']]
            other_findings = [f for f in findings['addresses'] if 'TARGET' not in f['type']]
            
            if target_findings:
                f.write("!!! TARGET ADDRESS MATCHES !!!\n")
                for finding in target_findings:
                    f.write(f"Offset: 0x{finding['offset']:X}\n")
                    f.write(f"Type: {finding['type']}\n")
                    f.write(f"Data: {finding['data']}\n")
                    f.write(f"Confidence: {finding['confidence']:.2f}\n\n")
            
            for finding in other_findings[:50]:  # Limit to first 50
                f.write(f"Offset: 0x{finding['offset']:X}\n")
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Address: {finding['data']}\n\n")
            
            # Private key findings
            f.write("\nPRIVATE KEY CANDIDATES:\n")
            f.write("-"*40 + "\n")
            
            # Sort by confidence
            sorted_keys = sorted(findings['private_keys'], 
                               key=lambda x: x['confidence'], 
                               reverse=True)
            
            for key in sorted_keys[:100]:  # Top 100 keys
                f.write(f"Offset: 0x{key['offset']:X}\n")
                f.write(f"Pattern: {key['pattern']}\n")
                f.write(f"Confidence: {key['confidence']:.2f}\n")
                f.write(f"Key (hex): {key['key_hex']}\n")
                
                # Try to derive address (would need proper implementation)
                addr = self.derive_address_from_private_key(key['key_hex'])
                if addr:
                    f.write(f"Derived Address: {addr}\n")
                    if addr == self.target_address:
                        f.write("!!! THIS KEY MATCHES TARGET ADDRESS !!!\n")
                
                f.write("\n")
            
            # Summary
            f.write("\n" + "="*40 + "\n")
            f.write("SUMMARY:\n")
            f.write(f"Berkeley DB signatures: {len(findings['berkeley_db'])}\n")
            f.write(f"Bitcoin addresses found: {len(findings['addresses'])}\n")
            f.write(f"Private key candidates: {len(findings['private_keys'])}\n")
            f.write(f"Target address found: {'YES' if target_findings else 'NO'}\n")
        
        print(f"\nReport saved to: {report_path}")
        
        # Generate extraction script
        self.generate_extraction_script(findings, output_dir)
    
    def generate_extraction_script(self, findings: Dict, output_dir: str):
        """
        Generate scripts for extracting and testing found data
        """
        # Python script for testing keys
        script_path = os.path.join(output_dir, "test_keys.py")
        
        with open(script_path, 'w') as f:
            f.write("#!/usr/bin/env python3\n")
            f.write("# Script to test recovered private keys\n\n")
            f.write("import hashlib\n")
            f.write("import binascii\n\n")
            f.write("target_address = '147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL'\n\n")
            f.write("# Recovered private keys (top candidates)\n")
            f.write("keys = [\n")
            
            for key in findings['private_keys'][:20]:
                f.write(f"    '{key['key_hex']}',  # Offset: 0x{key['offset']:X}\n")
            
            f.write("]\n\n")
            f.write("# Test each key\n")
            f.write("# Note: This requires proper secp256k1 implementation\n")
            f.write("# Install: pip install ecdsa bitcoin\n\n")
            f.write("print('Testing recovered keys...')\n")
            f.write("for i, key_hex in enumerate(keys):\n")
            f.write("    print(f'Testing key {i+1}: {key_hex[:8]}...')\n")
            f.write("    # Add your key testing logic here\n")
        
        os.chmod(script_path, 0o755)
        print(f"Testing script saved to: {script_path}")


def main():
    """
    Main entry point for advanced carver
    """
    if len(sys.argv) < 2:
        print("Usage: python advanced_wallet_carver.py <disk_image>")
        sys.exit(1)
    
    disk_image = sys.argv[1]
    
    if not os.path.exists(disk_image):
        print(f"Error: Disk image not found: {disk_image}")
        sys.exit(1)
    
    print("""
    ╔════════════════════════════════════════════════╗
    ║      Advanced Bitcoin Wallet Carver           ║
    ║         Forensic Recovery Tool                ║
    ╚════════════════════════════════════════════════╝
    """)
    
    carver = AdvancedWalletCarver(disk_image)
    
    # Run the scan
    findings = carver.scan_with_sliding_window()
    
    # Generate report
    carver.generate_detailed_report(findings)
    
    print("\n" + "="*60)
    print("Recovery complete!")
    print("Check ./recovery_output/ for detailed results")
    print("="*60)


if __name__ == "__main__":
    main()