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
