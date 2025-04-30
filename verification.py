"""Verify RSA digital signature embedded in an image using LSB steganography."""

import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from PIL import Image
import numpy as np


def load_public_key(public_key_path='public_key.pem'):
    """
    Loads a public RSA key from a file.

    Args:
        public_key_path (str): Path to the public key file.

    Returns:
        RSA.RsaKey: Loaded public key.
    """
    with open(public_key_path, 'rb') as key_file:
        return RSA.import_key(key_file.read())


def extract_signature(image_path, signature_length_bytes):
    """
    Extracts the signature from an image using LSB steganography.

    Args:
        image_path (str): Path to the signed image.
        signature_length_bytes (int): Length of the embedded signature in bytes.

    Returns:
        bytes: Extracted signature.
    """
    image = Image.open(image_path).convert('RGB')
    pixels = np.array(image, dtype=np.uint8)

    extracted_bits = []
    height, width, _ = pixels.shape
    bit_index = 0
    total_bits = signature_length_bytes * 8

    for y_pos in range(height):
        for x_pos in range(width):
            if bit_index >= total_bits:
                break
            if (x_pos + y_pos) % 16 == 0:
                red, _, _ = pixels[y_pos, x_pos]
                bit = red & 1
                extracted_bits.append(str(bit))
                bit_index += 1

    byte_chunks = [
        int(''.join(extracted_bits[i:i + 8]), 2)
        for i in range(0, len(extracted_bits), 8)
    ]

    return bytes(byte_chunks)


def verify_signature(original_image_path, signed_image_path, public_key):
    """
    Verifies the digital signature of an image.

    Args:
        original_image_path (str): Path to the original image.
        signed_image_path (str): Path to the signed image.
        public_key (RSA.RsaKey): Public RSA key.
    """
    signature_length = 4096 // 8  # 4096-bit key = 512 bytes signature
    extracted_signature = extract_signature(signed_image_path, signature_length)

    with Image.open(original_image_path) as image:
        image_bytes = image.tobytes()

    hash_obj = SHA256.new(image_bytes)

    try:
        pkcs1_15.new(public_key).verify(hash_obj, extracted_signature)
        print('✅ Signature is VALID!')
    except (ValueError, TypeError):
        print('❌ Signature verification FAILED!')


def main():
    """Main function to verify image signature."""
    original_image = 'original.png'
    signed_image = 'signed.png'

    if not os.path.exists(original_image) or not os.path.exists(signed_image):
        print('Error: Original or signed image not found.')
        return

    public_key = load_public_key()
    verify_signature(original_image, signed_image, public_key)


if __name__ == '__main__':
    main()
