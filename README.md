# Bitcoin Wallet.dat Recovery Tools

## Forensic Recovery Suite for 2011-Era Bitcoin Wallets

This suite provides advanced tools for recovering Bitcoin wallet.dat files from formatted hard drives, specifically optimized for wallets created around 2011.

## 🎯 Target Information
- **Target Address**: `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`
- **Wallet Era**: 2011 (likely Bitcoin Core v0.3.x - v0.5.x)
- **Expected Format**: Berkeley DB (BDB) version 9

## 📁 Files Included

1. **`bitcoin_wallet_recovery.py`** - Main recovery tool with comprehensive scanning
2. **`advanced_wallet_carver.py`** - Advanced carving with entropy analysis
3. **`setup_recovery_tools.sh`** - Automated setup script
4. **`run_recovery.sh`** - Launcher script (created by setup)

## 🚀 Quick Start

### 1. Initial Setup
```bash
# Make setup script executable
chmod +x setup_recovery_tools.sh

# Run setup (installs dependencies, creates workspace)
./setup_recovery_tools.sh

# Activate the virtual environment
source wallet_recovery_env/bin/activate
```

### 2. Run Recovery
```bash
# Basic recovery (recommended first attempt)
python3 bitcoin_wallet_recovery.py ~/Desktop/bitcoin_disk.img ./recovery_output

# Advanced carving (if basic recovery doesn't find wallet)
python3 advanced_wallet_carver.py ~/Desktop/bitcoin_disk.img
```

## 🔍 What These Tools Search For

### Berkeley DB Signatures
The tools search for multiple Berkeley DB magic bytes at various offsets:
- `0x00061561` - Berkeley DB Btree magic
- `0x00053162` - Berkeley DB Btree magic (older version)
- `0x62310500` - Reversed byte order (little-endian)
- Full wallet header: `00 00 00 00 01 00 00 00 00 00 00 00 62 31 05 00`

### Bitcoin-Specific Patterns
- **Private Keys**: 
  - ASN.1 structure: `0x0130820113020101042`
  - Raw 32-byte sequences with appropriate entropy
- **Wallet Entries**:
  - `key!` or `key\x21` - Key entry markers
  - `name` - Name entry markers
  - `defaultkey` - Default key markers
  - `pool` - Key pool markers
- **Bitcoin Addresses**:
  - Strings starting with `1` followed by 25-34 base58 characters
  - Specifically searching for: `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL`

## 📊 Recovery Process

### Stage 1: Quick Scan
Searches for Berkeley DB signatures to identify potential wallet locations.

### Stage 2: Region Carving
When a signature is found, carves out 10MB regions for detailed analysis.

### Stage 3: Key Extraction
Extracts potential private keys using multiple methods:
1. **ASN.1 Pattern Matching** - Looks for standard key structures
2. **Context-Based** - Finds 32-byte sequences near wallet markers
3. **Entropy Analysis** - Identifies high-entropy regions likely to be keys

### Stage 4: Validation
- Validates that extracted keys are within secp256k1 curve range
- Checks entropy levels (7.5-8.0 bits typical for private keys)
- Verifies keys aren't all zeros or ones

## 📄 Output Files

The tools generate several output files in the recovery directory:

### 1. Recovery Log
`recovery_log_[timestamp].txt` - Detailed log of the scanning process

### 2. Wallet Candidates
`wallet_candidate_[offset].dat` - Carved regions containing potential wallet data

### 3. Recovery Report
`recovery_report.txt` - Summary of findings including:
- Berkeley DB signatures found
- Bitcoin addresses discovered
- Private key candidates
- Confidence levels for each finding

### 4. Import Script
`import_keys.sh` - Bitcoin Core import script for recovered keys

### 5. Target Address Regions
`TARGET_ADDRESS_REGION_[offset].dat` - Special exports when target address is found

## 🔧 Advanced Usage

### Custom Scanning Parameters
```python
# Modify chunk size for faster/slower scanning
recovery_tool = WalletRecoveryTool(disk_image_path, output_dir)
recovery_tool.chunk_size = 209715200  # 200MB chunks
```

### Search Specific Regions
```python
# If you know approximate location
with open(disk_image_path, 'rb') as f:
    f.seek(0x1000000)  # Start at 16MB offset
    data = f.read(104857600)  # Read 100MB
    # Process data...
```

## ⚠️ Important Notes

### 1. **Work on Copies**
ALWAYS work on a copy of your disk image, never the original!

### 2. **False Positives**
The tools will find many false positives. This is normal. Review all candidates carefully.

### 3. **Memory Requirements**
For large disk images (>100GB), ensure you have sufficient RAM. The tools use chunked reading to minimize memory usage.

### 4. **Time Estimates**
- 160GB disk: ~2-4 hours (standard scan)
- 160GB disk: ~6-12 hours (deep scan)
- Times vary based on disk speed and CPU

### 5. **Encrypted Wallets**
If your wallet was encrypted (password-protected), you'll need additional tools like `btcrecover` or `hashcat` after finding the wallet data.

## 🔐 Next Steps After Recovery

### 1. Verify Wallet Data
Use `file` command to verify Berkeley DB format:
```bash
file wallet_candidate_*.dat
```

### 2. Test with Bitcoin Core
```bash
# Backup current wallet
mv ~/.bitcoin/wallet.dat ~/.bitcoin/wallet.dat.backup

# Copy recovered wallet
cp wallet_candidate_[offset].dat ~/.bitcoin/wallet.dat

# Start Bitcoin Core
bitcoin-qt -rescan
```

### 3. Use PyWallet for Key Extraction
```bash
# Install pywallet
git clone https://github.com/jackjack-jj/pywallet.git

# Dump wallet
python pywallet.py --dumpwallet --wallet=wallet_candidate.dat
```

### 4. Manual Key Import
If you have extracted private keys:
```bash
bitcoin-cli importprivkey "PRIVATE_KEY_HERE" "label" false
bitcoin-cli rescanblockchain
```

## 🆘 Troubleshooting

### Issue: "No wallet candidates found"
**Solution**: Try these approaches:
1. Run advanced_wallet_carver.py for deeper analysis
2. Increase chunk overlap size
3. Search for partial patterns
4. The wallet may be too fragmented

### Issue: "Too many false positives"
**Solution**: Focus on high-confidence findings:
1. Look for complete wallet headers
2. Check if Bitcoin addresses are found near Berkeley DB signatures
3. Prioritize regions with multiple pattern matches

### Issue: "Memory error on large disk"
**Solution**: Reduce chunk size:
```python
chunk_size = 52428800  # 50MB instead of 100MB
```

## 📚 Additional Resources

### Recommended Tools
1. **TestDisk/PhotoRec** - General file recovery
2. **R-Studio** - Commercial recovery with custom signatures
3. **DMDE** - Disk editor with pattern search
4. **PyWallet** - Python wallet manipulation tool
5. **btcrecover** - Password recovery for encrypted wallets

### Useful Commands
```bash
# Search for hex pattern in disk image
xxd -c 32 disk.img | grep "62 31 05 00"

# Extract specific offset range
dd if=disk.img of=extracted.dat bs=1M skip=100 count=10

# Check file type
file -b extracted.dat

# View hex at specific offset
hexdump -C -s 0x1000000 -n 1024 disk.img
```

## 🎯 Success Indicators

You've likely found your wallet when:
1. ✅ Target address `147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL` is found
2. ✅ Berkeley DB signature followed by Bitcoin-specific patterns
3. ✅ Multiple private key candidates in same region
4. ✅ Wallet metadata (version, minversion) found nearby
5. ✅ File command confirms: "Berkeley DB (Btree, version 9)"

## 💡 Pro Tips

1. **Start Simple**: Run standard recovery first before deep scanning
2. **Note Patterns**: If you find partial success, note the offset and search nearby
3. **Multiple Passes**: Sometimes running multiple times finds different candidates
4. **Cross-Reference**: If you find an address, search for its HASH160 too
5. **Keep Logs**: Save all output for later analysis

## ⚖️ Legal Notice

These tools are for recovering YOUR OWN Bitcoin wallets only. Do not use these tools on drives you don't own or without proper authorization.

## 🤝 Need Help?

If you successfully recover your wallet using these tools, consider:
1. Sharing your experience to help others
2. Contributing improvements to the codebase
3. Supporting open-source Bitcoin development

Good luck with your recovery! 🍀

---

**Remember**: The blockchain is permanent, but wallet files are fragile. Once you recover your wallet, make multiple secure backups immediately!