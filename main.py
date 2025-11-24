#!/usr/bin/env python3
"""
Main script for BTC Finder
"""

import sys
from btc_finder import BTCFinder


def main():
    """Main entry point for the BTC Finder application."""
    finder = BTCFinder()
    
    print("BTC Finder - Bitcoin Address Validator")
    print("=" * 40)
    
    # Example usage
    test_addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Genesis block address
        "3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy",  # P2SH address
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # Bech32 address
        "invalid_address",  # Invalid address
    ]
    
    for address in test_addresses:
        is_valid = finder.validate_address(address)
        address_type = finder.get_address_type(address)
        print(f"\nAddress: {address}")
        print(f"Valid: {is_valid}")
        print(f"Type: {address_type}")
    
    # Interactive mode if arguments provided
    if len(sys.argv) > 1:
        print("\n" + "=" * 40)
        print("Validating provided address:")
        user_address = sys.argv[1]
        is_valid = finder.validate_address(user_address)
        address_type = finder.get_address_type(user_address)
        print(f"\nAddress: {user_address}")
        print(f"Valid: {is_valid}")
        print(f"Type: {address_type}")


if __name__ == "__main__":
    main()
