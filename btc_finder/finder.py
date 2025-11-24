"""
Core BTC Finder module for Bitcoin address operations
"""

import hashlib
import base58


class BTCFinder:
    """
    A class for Bitcoin address generation and validation operations.
    """

    def __init__(self):
        """Initialize the BTCFinder instance."""
        pass

    @staticmethod
    def validate_address(address):
        """
        Validate a Bitcoin address.
        
        Args:
            address (str): The Bitcoin address to validate
            
        Returns:
            bool: True if the address is valid, False otherwise
        """
        try:
            if not address or not isinstance(address, str):
                return False
            
            # Bitcoin legacy addresses should be between 26-35 characters
            # Bech32 addresses can be up to 90 characters
            if address.startswith('bc1'):
                if len(address) < 14 or len(address) > 90:
                    return False
            else:
                if len(address) < 26 or len(address) > 35:
                    return False
            
            # Check if it starts with valid prefix (1, 3, or bc1)
            if not (address.startswith('1') or address.startswith('3') or address.startswith('bc1')):
                return False
            
            # For legacy addresses (starting with 1 or 3), validate with base58
            if address.startswith('1') or address.startswith('3'):
                try:
                    decoded = base58.b58decode(address)
                    # Check length (should be 25 bytes)
                    if len(decoded) != 25:
                        return False
                    # Verify checksum
                    payload = decoded[:-4]
                    checksum = decoded[-4:]
                    hash_result = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
                    return hash_result[:4] == checksum
                except Exception:
                    return False
            
            # For bech32 addresses (starting with bc1), basic validation
            if address.startswith('bc1'):
                # Basic bech32 character set validation (simplified)
                # Full bech32 validation would require checksum verification
                bech32_charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
                return all(c in bech32_charset for c in address[3:].lower())
            
            return False
        except Exception:
            return False

    @staticmethod
    def get_address_type(address):
        """
        Determine the type of Bitcoin address.
        
        Args:
            address (str): The Bitcoin address
            
        Returns:
            str: The type of address ('P2PKH', 'P2SH', 'Bech32', or 'Unknown')
        """
        if not address or not isinstance(address, str):
            return "Unknown"
        
        if address.startswith('1'):
            return "P2PKH"
        elif address.startswith('3'):
            return "P2SH"
        elif address.startswith('bc1'):
            return "Bech32"
        else:
            return "Unknown"
