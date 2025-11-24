# GitHub Copilot Instructions for Bitcoin Wallet Recovery Project

## Project Overview
This is a **forensic data carving tool** designed to recover a Bitcoin wallet.dat file from a formatted hard drive. The wallet was created in 2011 (Bitcoin Core v0.3.x - v0.5.x era) and contains a specific target address: `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`.

## Critical Context
- **Target**: 2011-era Bitcoin wallet.dat file on a formatted hard drive
- **File Format**: Berkeley DB (BDB) version 9 
- **Target Address**: `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`
- **Challenge**: Data is fragmented and scattered across unallocated disk space
- **Environment**: Python 3 with forensic data carving techniques

## Technical Specifications

### Berkeley DB Structure (2011 Wallets)
When suggesting code related to Berkeley DB detection:

1. **Primary Magic Bytes** (at offset 0x0C):
   - `0x62 0x31 0x05 0x00` (little-endian BDB v9)
   - `0x00 0x05 0x31 0x62` (big-endian variant)
   - `0x00 0x06 0x15 0x61` (BDB Btree magic)
   - `0x00 0x04 0x22 0x53` (alternative BDB version)

2. **Complete Wallet Header Pattern**:
   ```python
   # Full 2011 wallet.dat header (24 bytes)
   b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x62\x31\x05\x00\x09\x00\x00\x00\x00\x20\x00\x00'
   # Bytes 0-11: Page header
   # Bytes 12-15: BDB magic (0x62310500)
   # Bytes 16-19: BDB version (9)
   # Bytes 20-23: Page size (8KB = 0x00002000 or 4KB = 0x00001000)
   ```

3. **Page Sizes**: 2011 wallets typically use 4KB (4096 bytes) or 8KB (8192 bytes) pages

### Bitcoin Private Key Formats (2011 Era)

When generating code for private key extraction:

1. **ASN.1 Wrapped Keys** (most common in 2011):
   ```python
   # Pre-2012 unencrypted private key pattern
   prefix = b'\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20'
   # Followed by 32 bytes of actual private key
   
   # Alternative ASN.1 format
   prefix = b'\x30\x82\x01\x13\x02\x01\x01\x04\x20'
   ```

2. **Raw 32-byte Keys**:
   - Must be in range: `0x01` to `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140` (secp256k1 curve order - 1)
   - Typical entropy: 7.5 to 8.0 bits per byte
   - Must have at least 8 different byte values (minimum entropy requirement)

3. **Context Markers** (strings that appear near private keys):
   - `key!` or `key\x21` - Key entry marker in BDB
   - `name` - Name field (often precedes addresses)
   - `pool` - Key pool entries
   - `defaultkey` - Default wallet key
   - `ckey` - Encrypted key (if wallet was encrypted)
   - `mkey` - Master key (for encrypted wallets)

### Wallet Entry Structure

When working with wallet data parsing:

```python
# Typical 2011 wallet.dat entry structure:
# [4 bytes: entry length]
# [1 byte: entry type]
# [variable: key data]
# [1 byte: separator 0x00]
# [4 bytes: value length]
# [variable: value data]

# Entry types:
# "key" + 0x21 = public key entry (followed by private key)
# "name" = address label
# "version" = wallet version number
# "minversion" = minimum client version required
# "defaultkey" = default receive address
```

## Code Generation Guidelines

### 1. Chunked Reading Pattern
Always use chunked reading for large disk images to avoid memory issues:

```python
chunk_size = 104857600  # 100MB chunks
overlap = 65536  # 64KB overlap to catch boundary patterns

with open(disk_image_path, 'rb') as f:
    offset = 0
    while offset < file_size:
        f.seek(max(0, offset - overlap))
        chunk = f.read(chunk_size + overlap)
        actual_offset = max(0, offset - overlap)
        
        # Process chunk here
        
        offset += chunk_size
```

### 2. Pattern Searching Best Practices

When generating pattern search code:

```python
# ALWAYS search with boundary consideration
pos = 0
while pos < len(data) - len(pattern):
    found_pos = data.find(pattern, pos)
    if found_pos == -1:
        break
    
    actual_offset = base_offset + found_pos
    # Process finding
    
    pos = found_pos + 1  # Continue searching for multiple occurrences
```

### 3. Private Key Validation

All extracted private keys must pass these validations:

```python
def validate_private_key(key_data: bytes) -> bool:
    """Validate potential private key"""
    # 1. Must be exactly 32 bytes
    if len(key_data) != 32:
        return False
    
    # 2. Not all zeros or all 0xFF
    if all(b == 0 for b in key_data) or all(b == 0xFF for b in key_data):
        return False
    
    # 3. Must be less than secp256k1 curve order
    max_key = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140')
    if key_data >= max_key:
        return False
    
    # 4. Minimum entropy (at least 8 different byte values)
    if len(set(key_data)) < 8:
        return False
    
    # 5. Calculate Shannon entropy (should be 7.5 - 8.0 for random keys)
    entropy = calculate_entropy(key_data)
    if not (7.5 <= entropy <= 8.0):
        return False
    
    return True
```

### 4. Entropy Calculation

When generating entropy analysis code:

```python
import math
from collections import defaultdict

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0-8 bits per byte)"""
    if not data:
        return 0
    
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    
    entropy = 0
    data_len = len(data)
    for count in freq.values():
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    
    return entropy
```

### 5. Carving and Region Extraction

When carving data around findings:

```python
def carve_wallet_region(file_handle, offset: int, size: int = 10485760):
    """Carve 10MB region around potential wallet location"""
    try:
        # Start 1MB before the finding to catch wallet header
        start_offset = max(0, offset - 1048576)
        file_handle.seek(start_offset)
        return file_handle.read(size)
    except Exception as e:
        logging.error(f"Error carving at 0x{offset:X}: {e}")
        return b''
```

## Logging and Output Standards

### Progress Reporting
Always show detailed progress for long operations:

```python
def log(self, message: str, level: str = "INFO"):
    """Standard logging format"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [{level}] {message}"
    print(log_entry)
    self.log_file.write(log_entry + "\n")
    self.log_file.flush()

# Progress indicators for scanning
progress = (offset / file_size) * 100
print(f"\rScanning: {progress:.1f}% (offset 0x{offset:X})", end='')
```

### Critical Findings
Use prominent alerts for important findings:

```python
if target_address_found:
    print(f"\n{'='*60}")
    print(f"!!! TARGET ADDRESS FOUND AT OFFSET 0x{offset:X} !!!")
    print(f"{'='*60}\n")
    self.log(f"TARGET ADDRESS FOUND at 0x{offset:X}", "CRITICAL")
```

## Performance Optimization Guidelines

1. **Use `bytes.find()` instead of regex** for binary pattern matching (much faster)
2. **Limit key candidate extraction** to areas near Berkeley DB signatures (reduces false positives)
3. **Use stride/step values** when doing entropy scanning (e.g., check every 4 bytes instead of every byte)
4. **Implement early exit conditions** for validation functions
5. **Avoid reading the same disk region multiple times** - cache carved regions

## Security and Safety Practices

When generating code that handles disk images:

1. **ALWAYS work on copies**: Never modify the original disk image
2. **Use read-only file handles** when possible: `open(path, 'rb')`
3. **Validate file paths** before opening
4. **Use exception handling** around all file I/O operations
5. **Sanitize hex output** in logs (don't expose full private keys in console output)

```python
# Safe hex preview (first 8 characters only in logs)
key_preview = key_hex[:8] + "..."
print(f"Found key: {key_preview}")

# Full key only in secure output files
with open(secure_output, 'w') as f:
    f.write(f"Full key: {key_hex}\n")
```

## Testing and Validation

When generating test code:

1. **Create mock data** with known patterns for unit tests
2. **Test boundary conditions**: patterns at chunk boundaries, start of file, end of file
3. **Validate against known wallet.dat files** (test cases)
4. **Benchmark performance** on large files (100GB+ disk images)

## Output File Standards

### Carved Wallet Candidates
```python
# Naming convention
carved_filename = f"wallet_candidate_{offset:X}.dat"
carved_path = os.path.join(output_dir, carved_filename)

# Save with proper error handling
with open(carved_path, 'wb') as f:
    f.write(carved_data)
```

### Recovery Reports
```python
# Comprehensive report structure
report_sections = [
    "BERKELEY DB SIGNATURES FOUND",
    "BITCOIN ADDRESSES FOUND",
    "PRIVATE KEY CANDIDATES",
    "SUMMARY AND STATISTICS"
]

# Include confidence levels for all findings
# Sort findings by confidence (highest first)
# Provide hex previews for manual verification
```

## Common Pitfalls to Avoid

1. **Don't use regex on binary data** - use `bytes.find()` for patterns
2. **Don't load entire disk image into memory** - use chunked reading
3. **Don't skip overlapping chunks** - patterns can span chunk boundaries
4. **Don't ignore byte order** - test both little-endian and big-endian patterns
5. **Don't assume continuous data** - wallet.dat may be fragmented
6. **Don't over-validate early** - collect candidates first, validate later
7. **Don't forget to close file handles** - use context managers (`with` statements)

## Bitcoin-Specific Cryptography Notes

When implementing Bitcoin address derivation (if needed):

```python
# Bitcoin address from private key (high-level overview)
# 1. Private key (32 bytes) -> Public key (ECDSA secp256k1)
# 2. Public key -> SHA256 -> RIPEMD160 (20 bytes = HASH160)
# 3. Add version byte (0x00 for mainnet) -> Base58Check encode

# For verification purposes only - use established libraries:
# - ecdsa (for elliptic curve operations)
# - base58 (for address encoding)
# - hashlib (for SHA256)
# - Crypto.Hash.RIPEMD160 (for RIPEMD160)

# NEVER implement cryptography from scratch
```

## Target-Specific Optimizations

For this specific recovery targeting `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`:

1. **Decode target address to HASH160** and search for both formats
2. **If address is found**, carve a large region (5-10MB) around it
3. **Search for public key hash** (20 bytes) as well as ASCII address
4. **Prioritize regions** where target address appears near BDB signatures
5. **Look for the address in context**: `name"147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`

## Code Style Preferences

- Use **type hints** for function parameters and returns
- Include **comprehensive docstrings** for all functions
- Use **descriptive variable names** (e.g., `berkeley_db_offset` not `bdb_off`)
- Prefer **early returns** for validation functions
- Use **named tuples** or dataclasses for structured data
- Include **inline comments** for complex bit manipulations
- Format hex values consistently: `0x{value:X}` for uppercase hex

## Dependencies and Libraries

Prefer these libraries when suggesting imports:

```python
# Core Python (always available)
import os
import sys
import struct  # For binary data unpacking
import hashlib  # For SHA256
import binascii  # For hex conversion
import math  # For entropy calculations
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from collections import defaultdict, namedtuple

# Project dependencies (installed via setup)
import base58  # For Bitcoin address encoding
import ecdsa  # For elliptic curve operations (if needed)
from Crypto.Hash import RIPEMD160  # For address derivation
```

## When Generating New Features

Always consider:

1. **Memory efficiency** - will this work on a 160GB disk image?
2. **Time complexity** - how long will this take on large data?
3. **False positive rate** - how many incorrect matches will this generate?
4. **Confidence scoring** - how can we rank findings by likelihood?
5. **Resumability** - can we save progress and resume if interrupted?
6. **Output usefulness** - does this help identify the actual wallet/key?

## Example: Complete Pattern Search Function

When generating similar functions, follow this structure:

```python
def search_berkeley_db_signatures(self, data: bytes, base_offset: int) -> List[Dict]:
    """
    Search for Berkeley DB signatures in a data chunk
    
    Args:
        data: Binary data to search
        base_offset: Absolute offset of this data in disk image
        
    Returns:
        List of findings with offset, type, and confidence
    """
    findings = []
    
    for signature_info in self.berkeley_signatures:
        pattern = signature_info['pattern']
        sig_offset = signature_info.get('offset', 0)
        
        pos = 0
        while pos < len(data) - len(pattern):
            found_pos = data.find(pattern, pos)
            if found_pos == -1:
                break
            
            # Calculate absolute offset
            actual_offset = base_offset + found_pos - sig_offset
            
            # Avoid duplicate processing
            if actual_offset in self.processed_offsets:
                pos = found_pos + 1
                continue
            
            self.processed_offsets.add(actual_offset)
            
            # Extract context around finding
            context_start = max(0, found_pos - 512)
            context_end = min(len(data), found_pos + len(pattern) + 512)
            context = data[context_start:context_end]
            
            finding = {
                'offset': actual_offset,
                'type': signature_info['name'],
                'confidence': signature_info['confidence'],
                'context': context,
                'pattern_matched': pattern
            }
            
            findings.append(finding)
            self.log(f"Found {signature_info['name']} at 0x{actual_offset:X}")
            
            pos = found_pos + 1
    
    return findings
```

## Success Criteria

Code is considered successful if it:

1. ✅ Correctly identifies Berkeley DB v9 signatures
2. ✅ Extracts valid 32-byte private key candidates
3. ✅ Finds the target address `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`
4. ✅ Carves complete wallet regions around signatures
5. ✅ Minimizes false positives through proper validation
6. ✅ Handles 100GB+ disk images without memory errors
7. ✅ Provides clear, actionable output for next steps
8. ✅ Runs efficiently (reasonable scan time for large images)

---

**Remember**: This is forensic data recovery - prioritize completeness over speed, but balance against false positives. The goal is to recover the private key for address `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL` from a 2011-era wallet.dat file on a formatted hard drive.
