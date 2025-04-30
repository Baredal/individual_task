"""Image signing using RSA digital signature and LSB steganography."""

import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from PIL import Image
import numpy as np


def load_private_key(private_key_path='private_key.pem'):
    """
    Loads a private RSA key from a file.

    Args:
        private_key_path (str): Path to the private key file.

    Returns:
        RSA.RsaKey: Loaded private key.
    """
    with open(private_key_path, 'rb') as key_file:
        return RSA.import_key(key_file.read())


def create_image_signature(image_path, private_key):
    """
    Creates a digital signature from the image bytes.

    Args:
        image_path (str): Path to the input image.
        private_key (RSA.RsaKey): Private RSA key.

    Returns:
        bytes: RSA digital signature.
    """
    with Image.open(image_path) as image:
        image = image.convert('RGB')
        image_bytes = image.tobytes()

    hash_obj = SHA256.new(image_bytes)
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    print('Signature created')
    return signature


def embed_signature(image_path, signature, save_path):
    """
    Embeds the digital signature into the image using LSB steganography.

    Args:
        image_path (str): Path to the input image.
        signature (bytes): Digital signature to embed.
        save_path (str): Path to save the signed image.
    """
    image = Image.open(image_path).convert('RGB')
    pixels = np.array(image, dtype=np.uint8)

    signature_bits = ''.join(format(byte, '08b') for byte in signature)
    signature_length = len(signature_bits)

    height, width, _ = pixels.shape
    bit_index = 0

    for y_pos in range(height):
        for x_pos in range(width):
            if bit_index >= signature_length:
                break
            if (x_pos + y_pos) % 16 == 0:
                red, green, blue = pixels[y_pos, x_pos]
                bit = int(signature_bits[bit_index])
                red = (red & ~1) | bit  # Set LSB
                pixels[y_pos, x_pos] = (red, green, blue)
                bit_index += 1

    signed_image = Image.fromarray(pixels)
    signed_image.save(save_path)
    print(f'Image signed and saved as {save_path}')


def main():
    """Main function to execute image signing process."""
    original_image = 'original.png'
    output_image = 'signed.png'

    if not os.path.exists(original_image):
        print(f'Error: Input image {original_image} not found.')
        return

    private_key = load_private_key()
    signature = create_image_signature(original_image, private_key)
    embed_signature(original_image, signature, output_image)


if __name__ == '__main__':
    main()
