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
import time
from typing import List, Tuple, Optional, Set
from datetime import datetime, timedelta
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
        
    def validate_berkeley_db_context(self, data: bytes, magic_offset: int) -> tuple:
        """
        Validate Berkeley DB context and return confidence level
        
        Args:
            data: Chunk of data containing potential BDB magic
            magic_offset: Offset of magic bytes within data chunk
            
        Returns:
            Tuple of (is_valid, confidence_score, reason)
            confidence_score: 0.0-1.0 (0.3=low, 0.6=medium, 0.9=high)
        """
        # Need at least 28 bytes for validation
        if magic_offset < 12 or magic_offset + 16 > len(data):
            return (False, 0.3, "insufficient_context")
        
        page_header_start = magic_offset - 12
        if page_header_start < 0 or page_header_start + 28 > len(data):
            return (False, 0.3, "boundary_issue")
            
        page_header = data[page_header_start:page_header_start + 28]
        
        confidence = 0.3  # Start with low confidence
        issues = []
        
        # Check magic at offset 12
        magic_bytes = page_header[12:16]
        if magic_bytes == b'\x62\x31\x05\x00':
            confidence += 0.2
        
        # Check BDB version field (should be 7-9 for 2011 era)
        try:
            version_bytes = struct.unpack('<I', page_header[16:20])[0]
            if version_bytes in [7, 8, 9]:
                confidence += 0.3
            elif version_bytes < 20:  # Plausible version
                confidence += 0.1
            else:
                issues.append(f"version={version_bytes}")
        except:
            issues.append("version_unpack_error")
        
        # Check page size (should be power of 2, typically 2KB-16KB)
        try:
            if len(page_header) >= 24:
                page_size = struct.unpack('<I', page_header[20:24])[0]
                if page_size in [2048, 4096, 8192, 16384]:
                    confidence += 0.2
                elif page_size > 0 and page_size < 65536 and (page_size & (page_size - 1)) == 0:
                    confidence += 0.1  # Power of 2 but unusual size
                else:
                    issues.append(f"pagesize={page_size}")
        except:
            issues.append("pagesize_error")
        
        # Check page number (first few pages more likely)
        try:
            page_num = struct.unpack('<I', page_header[8:12])[0]
            if page_num == 0:
                confidence += 0.1  # First page is good
            elif page_num < 100:
                confidence += 0.05
            elif page_num > 10000:
                issues.append(f"pagenum={page_num}")
        except:
            issues.append("pagenum_error")
        
        reason = f"score={confidence:.2f}"
        if issues:
            reason += f" issues={','.join(issues)}"
            
        return (confidence >= 0.5, confidence, reason)
    
    def scan_for_berkeley_db(self, data: bytes, base_offset: int = 0) -> List[Tuple[int, str, float]]:
        """
        Scan for Berkeley DB signatures with confidence scoring
        
        Returns:
            List of (offset, description, confidence) tuples
        """
        findings = []
        
        # HIGHEST PRIORITY: Complete 2011 wallet headers (8KB pages)
        wallet_header_8k = b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x62\x31\x05\x00\x09\x00\x00\x00\x00\x20\x00\x00'
        offset = 0
        while offset < len(data) - len(wallet_header_8k):
            pos = data.find(wallet_header_8k, offset)
            if pos == -1:
                break
            actual_pos = base_offset + pos
            if actual_pos not in self.processed_offsets:
                findings.append((actual_pos, "Complete 2011 wallet.dat header v9 (8KB pages)", 0.95))
                self.processed_offsets.add(actual_pos)
            offset = pos + 1
        
        # Complete wallet header (4KB pages)
        wallet_header_4k = b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x62\x31\x05\x00\x09\x00\x00\x00\x00\x10\x00\x00'
        offset = 0
        while offset < len(data) - len(wallet_header_4k):
            pos = data.find(wallet_header_4k, offset)
            if pos == -1:
                break
            actual_pos = base_offset + pos
            if actual_pos not in self.processed_offsets:
                findings.append((actual_pos, "Complete 2011 wallet.dat header v9 (4KB pages)", 0.95))
                self.processed_offsets.add(actual_pos)
            offset = pos + 1
        
        # Search for BDB v9 magic with version (more specific than magic alone)
        bdb_v9_pattern = b'\x62\x31\x05\x00\x09\x00\x00\x00'
        offset = 0
        while offset < len(data) - len(bdb_v9_pattern):
            pos = data.find(bdb_v9_pattern, offset)
            if pos == -1:
                break
            
            # This should be at offset 12 in a page header
            actual_pos = base_offset + pos - 12 if pos >= 12 else base_offset + pos
            
            if actual_pos not in self.processed_offsets:
                # Validate context for better confidence
                is_valid, confidence, reason = self.validate_berkeley_db_context(data, pos)
                
                if confidence >= 0.6:  # Only report medium+ confidence
                    findings.append((actual_pos, f"Berkeley DB v9 signature (confidence: {confidence:.2f}, {reason})", confidence))
                    self.processed_offsets.add(actual_pos)
                # Even low confidence - still extract keys, just don't spam output
                elif confidence >= 0.3:
                    findings.append((actual_pos, f"Possible BDB v9 fragment (low confidence: {confidence:.2f})", confidence))
                    self.processed_offsets.add(actual_pos)
            
            offset = pos + 1
        
        # Also check for OTHER Berkeley DB signatures from the original list
        # but with context validation
        other_signatures = [
            (b'\x00\x06\x15\x61', 'Berkeley DB Btree magic (0x00061561)'),
            (b'\x00\x05\x31\x62', 'Berkeley DB Btree magic (0x00053162)'),
        ]
        
        for signature, description in other_signatures:
            offset = 0
            while offset < len(data) - len(signature):
                pos = data.find(signature, offset)
                if pos == -1:
                    break
                
                # These signatures should appear at offset 12
                actual_pos = base_offset + pos - 12 if pos >= 12 else base_offset + pos
                
                if actual_pos not in self.processed_offsets:
                    # Lighter validation for alternative signatures
                    confidence = 0.5  # Medium confidence by default
                    findings.append((actual_pos, f"{description} (unvalidated)", confidence))
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
    
    def carve_wallet_region(self, file_handle, offset: int, size: int = 2097152) -> bytes:
        """
        Carve out a region around a potential wallet location
        
        For 2011 minimal-use wallets:
        - Typical size: 60-125 KB (metadata + key pool + 1-2 keys)
        - Page size: 4KB or 8KB
        - Strategy: Start before the signature to catch page 0, extend after
        
        Args:
            file_handle: File handle to disk image
            offset: Starting offset (usually points to page 0 or metadata page)
            size: Size to carve (default 2MB for high confidence)
            
        Returns:
            Carved data bytes
        """
        try:
            # For wallet.dat, the offset typically points to page 0 (metadata page)
            # We want to start from there and read forward
            # Also read a bit backwards in case we're at a middle page
            read_before = min(65536, offset)  # Read up to 64KB before (catch earlier pages)
            start_offset = offset - read_before
            total_size = size + read_before
            
            file_handle.seek(max(0, start_offset))
            carved_data = file_handle.read(total_size)
            
            # Log carving details for high-value findings
            if size >= 524288:  # If carving 512KB or more
                self.log(f"Carved {len(carved_data)} bytes from 0x{start_offset:X} to 0x{start_offset + len(carved_data):X}")
            
            return carved_data
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
            
            # Track statistics for progress
            start_time = time.time()
            total_findings = 0
            last_log_time = start_time
            
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
                    
                    # Progress update with enhanced information
                    progress = (offset / file_size) * 100
                    elapsed = time.time() - start_time
                    
                    if elapsed > 0:
                        speed_mb_s = (offset / (1024 * 1024)) / elapsed
                        remaining_bytes = file_size - offset
                        eta_seconds = remaining_bytes / (offset / elapsed) if offset > 0 else 0
                        eta = str(timedelta(seconds=int(eta_seconds)))
                    else:
                        speed_mb_s = 0
                        eta = "calculating..."
                    
                    # Print inline progress (overwrites same line)
                    progress_msg = (f"\rProgress: {progress:.1f}% | "
                                  f"Offset: 0x{offset:X} | "
                                  f"Speed: {speed_mb_s:.1f} MB/s | "
                                  f"ETA: {eta} | "
                                  f"Findings: {total_findings}")
                    print(progress_msg, end='', flush=True)
                    
                    # Log to file every 5% or every 60 seconds
                    current_time = time.time()
                    if progress % 5 < 0.1 or (current_time - last_log_time) > 60:
                        self.log(f"Chunk {chunk_num}: {progress:.1f}% complete - {total_findings} findings so far")
                        last_log_time = current_time
                    
                    # Scan for Berkeley DB signatures
                    berkeley_findings = self.scan_for_berkeley_db(chunk, actual_offset)
                    for finding_offset, description, confidence in berkeley_findings:
                        total_findings += 1
                        
                        # Only print for medium+ confidence to reduce spam
                        if confidence >= 0.6:
                            print()  # New line before important finding
                            self.log(f"Found Berkeley DB signature at 0x{finding_offset:X}: {description}")
                        elif confidence >= 0.9:
                            print()
                            self.log(f"!!! HIGH CONFIDENCE WALLET HEADER at 0x{finding_offset:X}: {description} !!!", "CRITICAL")
                        
                        # ALWAYS carve and extract keys, even from low confidence findings
                        # (formatted drive = fragmented data, can't be too picky)
                        
                        # Smart carving size based on confidence level:
                        # HIGH (0.8+): 2MB - likely complete wallet header, grab comprehensive region
                        # MEDIUM (0.5-0.8): 512KB - probably wallet fragment, moderate search
                        # LOW (0.3-0.5): 128KB - possible false positive, minimal carve
                        if confidence >= 0.8:
                            carve_size = 2097152  # 2MB
                        elif confidence >= 0.5:
                            carve_size = 524288   # 512KB
                        else:
                            carve_size = 131072   # 128KB
                        
                        carved_data = self.carve_wallet_region(f, finding_offset, carve_size)
                        
                        # Save carved region with confidence in filename
                        conf_label = "HIGH" if confidence >= 0.8 else "MED" if confidence >= 0.5 else "LOW"
                        carved_filename = os.path.join(self.output_dir, f"wallet_candidate_{conf_label}_{finding_offset:X}.dat")
                        with open(carved_filename, 'wb') as carved_file:
                            carved_file.write(carved_data)
                        
                        if confidence >= 0.6:
                            self.log(f"Saved carved data to {carved_filename}")
                        
                        # Create wallet candidate
                        confidence_str = "HIGH" if confidence >= 0.8 else "MEDIUM" if confidence >= 0.5 else "LOW"
                        candidate = WalletCandidate(
                            offset=finding_offset,
                            signature_type=description,
                            confidence=confidence_str,
                            data_preview=carved_data[:1024]
                        )
                        self.wallet_candidates.append(candidate)
                        
                        # CRITICAL: Extract keys from ALL regions (even low confidence)
                        # On a formatted drive, we need to be aggressive
                        keys = self.extract_potential_keys(carved_data, finding_offset)
                        if keys:
                            if confidence >= 0.6:
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
                        total_findings += 1
                        print()  # New line before important finding
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
            
            # Final newline after progress bar
            print()
            
            # Log final statistics
            total_time = time.time() - start_time
            self.log(f"Scan completed in {str(timedelta(seconds=int(total_time)))}")
            self.log(f"Total findings: {total_findings}")
                    
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