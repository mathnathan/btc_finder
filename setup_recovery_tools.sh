#!/bin/bash
# Bitcoin Wallet Recovery Tools - Setup Script
# This script installs required dependencies and prepares the recovery environment

echo "============================================"
echo "Bitcoin Wallet Recovery Tools Setup"
echo "============================================"
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
echo "Python version: $python_version"

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv wallet_recovery_env
source wallet_recovery_env/bin/activate

# Install required packages
echo "Installing required Python packages..."
pip install --upgrade pip

# Core packages
pip install base58
pip install ecdsa
pip install pycryptodome
pip install mnemonic

# Optional but useful packages
pip install bitcoin
pip install pybitcointools
pip install colorama
pip install tqdm

# Create recovery workspace
echo "Creating recovery workspace..."
mkdir -p recovery_workspace
mkdir -p recovery_workspace/outputs
mkdir -p recovery_workspace/candidates
mkdir -p recovery_workspace/logs

# Create configuration file
cat > recovery_workspace/config.ini << EOF
[Recovery Settings]
target_address = 147UbzE5mfmUkjY1Cvm4C3DQJzczUJn1VL
chunk_size_mb = 100
overlap_kb = 64
max_key_candidates = 1000
save_carved_wallets = true
output_format = both

[Search Patterns]
search_berkeley_db = true
search_private_keys = true
search_addresses = true
search_encrypted = true

[Performance]
use_multiprocessing = false
num_threads = 4
memory_limit_gb = 8
EOF

echo "Configuration file created at recovery_workspace/config.ini"

# Create launcher script
cat > run_recovery.sh << 'EOF'
#!/bin/bash
# Bitcoin Wallet Recovery Launcher

echo "Bitcoin Wallet Recovery Tool"
echo "============================"
echo ""

# Activate virtual environment
source wallet_recovery_env/bin/activate

# Check if disk image path is provided
if [ $# -eq 0 ]; then
    echo "Usage: ./run_recovery.sh <disk_image_path>"
    echo "Example: ./run_recovery.sh ~/Desktop/bitcoin_disk.img"
    exit 1
fi

DISK_IMAGE=$1
OUTPUT_DIR="recovery_workspace/outputs/recovery_$(date +%Y%m%d_%H%M%S)"

echo "Disk image: $DISK_IMAGE"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Check if disk image exists
if [ ! -f "$DISK_IMAGE" ]; then
    echo "Error: Disk image not found: $DISK_IMAGE"
    exit 1
fi

# Get disk image size
SIZE=$(stat -f%z "$DISK_IMAGE" 2>/dev/null || stat --format=%s "$DISK_IMAGE" 2>/dev/null)
SIZE_GB=$(echo "scale=2; $SIZE / 1073741824" | bc 2>/dev/null || echo "Unknown")
echo "Disk image size: $SIZE_GB GB"
echo ""

echo "Select recovery mode:"
echo "1) Quick scan (Berkeley DB signatures only)"
echo "2) Standard recovery (recommended)"
echo "3) Deep scan (comprehensive but slow)"
echo "4) Advanced carving (experimental)"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        echo "Starting quick scan..."
        python3 bitcoin_wallet_recovery.py "$DISK_IMAGE" "$OUTPUT_DIR" --quick
        ;;
    2)
        echo "Starting standard recovery..."
        python3 bitcoin_wallet_recovery.py "$DISK_IMAGE" "$OUTPUT_DIR"
        ;;
    3)
        echo "Starting deep scan..."
        python3 bitcoin_wallet_recovery.py "$DISK_IMAGE" "$OUTPUT_DIR" --deep
        ;;
    4)
        echo "Starting advanced carving..."
        python3 advanced_wallet_carver.py "$DISK_IMAGE"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "Recovery process completed!"
echo "Check the output directory for results."
EOF

chmod +x run_recovery.sh

echo ""
echo "============================================"
echo "Setup Complete!"
echo "============================================"
echo ""
echo "To start recovery:"
echo "1. Place your disk image in an accessible location"
echo "2. Run: ./run_recovery.sh /path/to/your/disk.img"
echo ""
echo "Virtual environment created: wallet_recovery_env"
echo "Activate it with: source wallet_recovery_env/bin/activate"
echo ""