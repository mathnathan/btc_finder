# BTC Finder

A Python tool for Bitcoin address validation and operations.

## Features

- Bitcoin address validation (P2PKH, P2SH, Bech32)
- Address type detection
- Easy-to-use Python API

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mathnathan/btc_finder.git
cd btc_finder
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line

Run the main script to see example validations:
```bash
python main.py
```

Validate a specific address:
```bash
python main.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

### As a Python Module

```python
from btc_finder import BTCFinder

finder = BTCFinder()

# Validate an address
is_valid = finder.validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
print(f"Valid: {is_valid}")

# Get address type
address_type = finder.get_address_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
print(f"Type: {address_type}")  # Output: P2PKH
```

## Supported Address Types

- **P2PKH** (Pay-to-Public-Key-Hash): Addresses starting with `1`
- **P2SH** (Pay-to-Script-Hash): Addresses starting with `3`
- **Bech32** (SegWit): Addresses starting with `bc1`

## Requirements

- Python 3.6+
- base58

## License

MIT License