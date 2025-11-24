#!/usr/bin/env python3
"""
Bitcoin Wallet.dat Recovery Tool
Forensic data recovery tool for finding Bitcoin wallet.dat files on formatted hard drives
Designed for disk images from 2011-era Bitcoin wallets
"""

import os
import sys
import struct
import hashlib
import binascii
import mmap
import re
from typing import List, Tuple, Optional, Set
from datetime import datetime
from collections import namedtuple

# Data structures for findings
WalletCandidate = namedtuple('WalletCandidate', ['offset', 'signature_type', 'confidence', 'data_preview'])
KeyCandidate = namedtuple('KeyCandidate', ['offset', 'key_type', 'key_data', 'address'])

class WalletRecoveryTool:
    """
    Comprehensive Bitcoin wallet.dat recovery tool for forensic analysis
    """
    
    def __init__(self, disk_image_path: str, output_dir: str = "./recovery_output"):
        """
        Initialize the wallet recovery tool
        
        Args:
            disk_image_path: Path to the disk image file
            output_dir: Directory to save recovered data
        """
        self.disk_image_path = disk_image_path
        self.output_dir = output_dir
        self.target_address = "147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL"
        self.wallet_candidates = []
        self.key_candidates = []
        self.processed_offsets = set()
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Log file for findings
        self.log_file = open(os.path.join(output_dir, f"recovery_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"), 'w')
        
        # Berkeley DB Magic Bytes (various versions)
        self.berkeley_signatures = [
            # Format: (offset, signature_bytes, description)
            (0x00, b'\x00\x06\x15\x61', 'Berkeley DB Btree magic (0x00061561)'),
            (0x00, b'\x61\x15\x06\x00', 'Berkeley DB Btree magic reversed'),
            (0x00, b'\x00\x05\x31\x62', 'Berkeley DB Btree magic (0x00053162)'),
            (0x00, b'\x62\x31\x05\x00', 'Berkeley DB Btree magic reversed'),
            (0x0C, b'\x00\x06\x15\x61', 'Berkeley DB Btree magic at offset 12'),
            (0x0C, b'\x61\x15\x06\x00', 'Berkeley DB Btree magic reversed at offset 12'),
            (0x0C, b'\x00\x05\x31\x62', 'Berkeley DB Btree magic at offset 12'),
            (0x0C, b'\x62\x31\x05\x00', 'Berkeley DB Btree magic reversed at offset 12'),
            (0x0C, b'\x00\x04\x22\x53', 'Berkeley DB Btree magic (0x00042253)'),
            (0x0C, b'\x53\x22\x04\x00', 'Berkeley DB Btree magic reversed'),
            (0x0C, b'\x00\x04\x09\x88', 'Berkeley DB Btree magic (0x00040988)'),
            (0x0C, b'\x88\x09\x04\x00', 'Berkeley DB Btree magic reversed'),
        ]
        
        # Full wallet.dat header pattern (common in 2011 wallets)
        self.wallet_header_pattern = b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x62\x31\x05\x00'
        
        # Bitcoin-specific patterns
        self.bitcoin_patterns = [
            # Private key patterns
            (b'\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20', 'Pre-2012 unencrypted private key'),
            (b'\x01\xd6\x30\x81\xd3\x02\x01\x01\x04\x20', 'Post-2012 unencrypted private key'),
            (b'\x30\x82\x01\x13\x02\x01\x01', 'ASN.1 private key structure'),
            (b'\x30\x81\xd3\x02\x01\x01', 'ASN.1 private key structure (variant)'),
            
            # Wallet entry patterns
            (b'key\x21', 'Wallet key entry marker'),
            (b'ckey', 'Encrypted key marker'),
            (b'mkey', 'Master key marker'),
            (b'name', 'Name entry marker'),
            (b'defaultkey', 'Default key marker'),
            (b'version', 'Version marker'),
            (b'minversion', 'Min version marker'),
            (b'pool', 'Key pool marker'),
            
            # Address patterns (looking for our specific address)
            (self.target_address.encode('ascii'), 'Target Bitcoin address'),
            (b'147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL', 'Target address (explicit)'),
        ]
        
        # Patterns that often appear near keys
        self.key_proximity_patterns = [
            b'name"1',  # Often precedes Bitcoin addresses
            b'"1',      # Short version
            b'\x00\x01\x04\x20',  # Common before private key data
        ]
        
    def log(self, message: str, level: str = "INFO"):
        """Write to log file and console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        self.log_file.write(log_entry + "\n")
        self.log_file.flush()
        
    def scan_for_berkeley_db(self, data: bytes, base_offset: int = 0) -> List[Tuple[int, str]]:
        """
        Scan for Berkeley DB signatures
        
        Returns:
            List of (offset, description) tuples
        """
        findings = []
        
        for sig_offset, signature, description in self.berkeley_signatures:
            # Search for signature in data
            offset = 0
            while offset < len(data) - len(signature):
                pos = data.find(signature, offset)
                if pos == -1:
                    break
                    
                actual_pos = base_offset + pos - sig_offset
                if actual_pos >= 0 and actual_pos not in self.processed_offsets:
                    findings.append((actual_pos, description))
                    self.processed_offsets.add(actual_pos)
                    
                offset = pos + 1
                
        # Search for full wallet header
        offset = 0
        while offset < len(data) - len(self.wallet_header_pattern):
            pos = data.find(self.wallet_header_pattern, offset)
            if pos == -1:
                break
                
            actual_pos = base_offset + pos
            if actual_pos not in self.processed_offsets:
                findings.append((actual_pos, "Full wallet.dat header pattern"))
                self.processed_offsets.add(actual_pos)
                
            offset = pos + 1
            
        return findings
    
    def scan_for_bitcoin_patterns(self, data: bytes, base_offset: int = 0) -> List[Tuple[int, str]]:
        """
        Scan for Bitcoin-specific patterns
        
        Returns:
            List of (offset, description) tuples
        """
        findings = []
        
        for pattern, description in self.bitcoin_patterns:
            offset = 0
            while offset < len(data) - len(pattern):
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                    
                actual_pos = base_offset + pos
                findings.append((actual_pos, description))
                
                # If we found the target address, this is high priority
                if b'147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL' in pattern:
                    self.log(f"!!! FOUND TARGET ADDRESS at offset 0x{actual_pos:X} !!!", "CRITICAL")
                    
                offset = pos + 1
                
        return findings
    
    def extract_potential_keys(self, data: bytes, offset: int) -> List[bytes]:
        """
        Extract potential private keys from a data region
        
        Args:
            data: Data to search in
            offset: Starting offset in the data
            
        Returns:
            List of potential 32-byte private keys
        """
        keys = []
        
        # Look for ASN.1 private key structures
        asn1_patterns = [
            b'\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20',
            b'\x01\xd6\x30\x81\xd3\x02\x01\x01\x04\x20',
        ]
        
        for pattern in asn1_patterns:
            pos = 0
            while pos < len(data) - len(pattern) - 32:
                found = data.find(pattern, pos)
                if found == -1:
                    break
                    
                # Extract the 32 bytes following the pattern
                key_data = data[found + len(pattern):found + len(pattern) + 32]
                if len(key_data) == 32 and not all(b == 0 for b in key_data):
                    keys.append(key_data)
                    self.log(f"Found potential private key at offset 0x{offset + found:X}")
                    
                pos = found + 1
                
        # Also look for raw 32-byte sequences that could be keys
        # Check for sequences that look like keys (not all zeros, not all ones)
        for i in range(0, len(data) - 32, 1):
            potential_key = data[i:i+32]
            
            # Basic validation - not all zeros or ones
            if (not all(b == 0 for b in potential_key) and 
                not all(b == 0xFF for b in potential_key) and
                len(set(potential_key)) > 4):  # Has some entropy
                
                # Check if preceded by key markers
                for marker in self.key_proximity_patterns:
                    if i >= len(marker):
                        if data[i-len(marker):i].endswith(marker):
                            keys.append(potential_key)
                            self.log(f"Found potential raw key at offset 0x{offset + i:X}")
                            break
                            
        return keys
    
    def carve_wallet_region(self, file_handle, offset: int, size: int = 10485760) -> bytes:
        """
        Carve out a region around a potential wallet location
        
        Args:
            file_handle: File handle to disk image
            offset: Starting offset
            size: Size to carve (default 10MB)
            
        Returns:
            Carved data bytes
        """
        try:
            file_handle.seek(max(0, offset))
            return file_handle.read(size)
        except Exception as e:
            self.log(f"Error carving region at offset 0x{offset:X}: {e}", "ERROR")
            return b''
    
    def validate_bitcoin_address(self, address: str) -> bool:
        """
        Validate a Bitcoin address using Base58Check
        
        Args:
            address: Bitcoin address string
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Base58 alphabet
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            
            # Decode base58
            decoded = 0
            for char in address:
                decoded = decoded * 58 + alphabet.index(char)
                
            # Convert to bytes
            decoded_bytes = decoded.to_bytes(25, byteorder='big')
            
            # Check checksum
            checksum = hashlib.sha256(hashlib.sha256(decoded_bytes[:-4]).digest()).digest()[:4]
            
            return checksum == decoded_bytes[-4:]
        except:
            return False
    
    def scan_disk_image(self):
        """
        Main scanning function - scans the entire disk image
        """
        self.log(f"Starting scan of disk image: {self.disk_image_path}")
        
        try:
            file_size = os.path.getsize(self.disk_image_path)
            self.log(f"Disk image size: {file_size:,} bytes ({file_size / (1024**3):.2f} GB)")
            
            # Chunk size for reading (100MB chunks)
            chunk_size = 104857600  # 100MB
            overlap = 65536  # 64KB overlap to catch patterns on boundaries
            
            with open(self.disk_image_path, 'rb') as f:
                offset = 0
                chunk_num = 0
                
                while offset < file_size:
                    # Read chunk with overlap
                    f.seek(max(0, offset - overlap))
                    chunk = f.read(chunk_size + overlap)
                    
                    if not chunk:
                        break
                    
                    chunk_num += 1
                    actual_offset = max(0, offset - overlap)
                    
                    # Progress update
                    progress = (offset / file_size) * 100
                    self.log(f"Scanning chunk {chunk_num} - Offset: 0x{offset:X} ({progress:.2f}% complete)")
                    
                    # Scan for Berkeley DB signatures
                    berkeley_findings = self.scan_for_berkeley_db(chunk, actual_offset)
                    for finding_offset, description in berkeley_findings:
                        self.log(f"Found Berkeley DB signature at 0x{finding_offset:X}: {description}")
                        
                        # Carve out region around Berkeley DB header
                        self.log(f"Carving potential wallet region at 0x{finding_offset:X}")
                        carved_data = self.carve_wallet_region(f, finding_offset, 10485760)  # 10MB
                        
                        # Save carved region
                        carved_filename = os.path.join(self.output_dir, f"wallet_candidate_{finding_offset:X}.dat")
                        with open(carved_filename, 'wb') as carved_file:
                            carved_file.write(carved_data)
                        self.log(f"Saved carved data to {carved_filename}")
                        
                        # Create wallet candidate
                        candidate = WalletCandidate(
                            offset=finding_offset,
                            signature_type=description,
                            confidence="HIGH" if "Full wallet" in description else "MEDIUM",
                            data_preview=carved_data[:1024]
                        )
                        self.wallet_candidates.append(candidate)
                        
                        # Extract potential keys from carved region
                        keys = self.extract_potential_keys(carved_data, finding_offset)
                        if keys:
                            self.log(f"Extracted {len(keys)} potential private keys from region")
                            for key in keys:
                                self.key_candidates.append(KeyCandidate(
                                    offset=finding_offset,
                                    key_type="raw_private_key",
                                    key_data=key,
                                    address=None  # Would need to derive address
                                ))
                    
                    # Scan for Bitcoin patterns
                    bitcoin_findings = self.scan_for_bitcoin_patterns(chunk, actual_offset)
                    for finding_offset, description in bitcoin_findings:
                        self.log(f"Found Bitcoin pattern at 0x{finding_offset:X}: {description}")
                        
                        # If it's the target address, carve surrounding area
                        if "Target" in description:
                            self.log(f"!!! CARVING AREA AROUND TARGET ADDRESS !!!", "CRITICAL")
                            carved_data = self.carve_wallet_region(f, finding_offset - 1048576, 5242880)  # 5MB before and after
                            
                            carved_filename = os.path.join(self.output_dir, f"TARGET_ADDRESS_REGION_{finding_offset:X}.dat")
                            with open(carved_filename, 'wb') as carved_file:
                                carved_file.write(carved_data)
                            self.log(f"Saved target address region to {carved_filename}", "CRITICAL")
                    
                    offset += chunk_size
                    
        except Exception as e:
            self.log(f"Error during scan: {e}", "ERROR")
            raise
    
    def analyze_candidates(self):
        """
        Analyze found wallet candidates and generate report
        """
        self.log("\n" + "="*80)
        self.log("ANALYSIS SUMMARY")
        self.log("="*80)
        
        self.log(f"Total wallet candidates found: {len(self.wallet_candidates)}")
        self.log(f"Total key candidates found: {len(self.key_candidates)}")
        
        # Group by confidence
        high_confidence = [c for c in self.wallet_candidates if c.confidence == "HIGH"]
        medium_confidence = [c for c in self.wallet_candidates if c.confidence == "MEDIUM"]
        
        self.log(f"High confidence candidates: {len(high_confidence)}")
        self.log(f"Medium confidence candidates: {len(medium_confidence)}")
        
        # Write detailed report
        report_file = os.path.join(self.output_dir, "recovery_report.txt")
        with open(report_file, 'w') as f:
            f.write("Bitcoin Wallet Recovery Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Disk Image: {self.disk_image_path}\n")
            f.write(f"Target Address: {self.target_address}\n")
            f.write("\n" + "="*80 + "\n\n")
            
            f.write("WALLET CANDIDATES:\n")
            f.write("-"*40 + "\n")
            for candidate in self.wallet_candidates:
                f.write(f"Offset: 0x{candidate.offset:X}\n")
                f.write(f"Type: {candidate.signature_type}\n")
                f.write(f"Confidence: {candidate.confidence}\n")
                f.write(f"Preview (hex): {binascii.hexlify(candidate.data_preview[:64]).decode()}\n")
                f.write("-"*40 + "\n")
            
            f.write("\nKEY CANDIDATES:\n")
            f.write("-"*40 + "\n")
            for key in self.key_candidates[:100]:  # Limit to first 100 keys in report
                f.write(f"Offset: 0x{key.offset:X}\n")
                f.write(f"Type: {key.key_type}\n")
                f.write(f"Key (hex): {binascii.hexlify(key.key_data).decode()}\n")
                f.write("-"*40 + "\n")
        
        self.log(f"Detailed report saved to {report_file}")
    
    def run_recovery(self):
        """
        Run the complete recovery process
        """
        self.log("="*80)
        self.log("Bitcoin Wallet.dat Recovery Tool")
        self.log(f"Target Address: {self.target_address}")
        self.log("="*80)
        
        try:
            # Run the scan
            self.scan_disk_image()
            
            # Analyze results
            self.analyze_candidates()
            
            # Generate recovery script
            self.generate_recovery_script()
            
            self.log("\n" + "="*80)
            self.log("RECOVERY COMPLETE")
            self.log(f"Check {self.output_dir} for results")
            self.log("="*80)
            
        except Exception as e:
            self.log(f"Fatal error during recovery: {e}", "ERROR")
            raise
        finally:
            self.log_file.close()
    
    def generate_recovery_script(self):
        """
        Generate a script to import found keys into Bitcoin Core
        """
        script_file = os.path.join(self.output_dir, "import_keys.sh")
        with open(script_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# Bitcoin Core key import script\n")
            f.write("# Generated by wallet recovery tool\n\n")
            f.write("# WARNING: Only run this on a secure, offline system\n\n")
            
            for i, key in enumerate(self.key_candidates[:50]):  # Limit to first 50 keys
                key_hex = binascii.hexlify(key.key_data).decode()
                f.write(f"# Key {i+1} from offset 0x{key.offset:X}\n")
                f.write(f'bitcoin-cli importprivkey "L{key_hex}" "recovered_key_{i}" false\n')
            
            f.write("\n# Rescan blockchain after importing all keys\n")
            f.write("bitcoin-cli rescanblockchain\n")
        
        os.chmod(script_file, 0o755)
        self.log(f"Import script saved to {script_file}")


def main():
    """
    Main entry point
    """
    print("""
    ╔════════════════════════════════════════════════╗
    ║     Bitcoin Wallet.dat Forensic Recovery      ║
    ║          Specialized for 2011 Wallets         ║
    ╚════════════════════════════════════════════════╝
    """)
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python bitcoin_wallet_recovery.py <disk_image_path> [output_directory]")
        print("Example: python bitcoin_wallet_recovery.py ~/Desktop/bitcoin_disk.img ./recovery_output")
        sys.exit(1)
    
    disk_image_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./recovery_output"
    
    # Verify disk image exists
    if not os.path.exists(disk_image_path):
        print(f"Error: Disk image not found: {disk_image_path}")
        sys.exit(1)
    
    # Create recovery tool instance
    recovery_tool = WalletRecoveryTool(disk_image_path, output_dir)
    
    # Run recovery
    recovery_tool.run_recovery()
    
    print("\nRecovery process complete. Check the output directory for results.")
    print("\nNEXT STEPS:")
    print("1. Review the recovery_report.txt file")
    print("2. Examine the carved wallet_candidate_*.dat files")
    print("3. Use the import_keys.sh script with Bitcoin Core (on a secure system)")
    print("4. Consider using additional tools like pywallet on the carved files")
    print("\nIMPORTANT: Always work on copies, never the original disk image!")


if __name__ == "__main__":
    main()