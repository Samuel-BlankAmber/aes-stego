import sys
import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
from PIL import Image


def encode_message(width, height, padded_message):
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)
    iv = os.urandom(16)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    message_length_bytes = pad(len(padded_message).to_bytes(4), 16)
    message_length_encrypted = cipher.encrypt(message_length_bytes)
    assert len(message_length_encrypted) == 16

    ciphertext = cipher.encrypt(padded_message)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(iv + message_length_encrypted + ciphertext)
    mac = hmac.digest()

    data_length = width * height * 3

    data = aes_key + hmac_key + iv + mac + message_length_encrypted + ciphertext
    data += b"\x00" * (len(data) % 3)
    extra_data_needed = data_length - len(data)
    data += os.urandom(extra_data_needed)

    pixel_data = [tuple(data[i:i + 3]) for i in range(0, len(data), 3)]
    return pixel_data


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: %s <width> <height> <message> <output_image>" %
              sys.argv[0])
        sys.exit(1)

    width = int(sys.argv[1])
    height = int(sys.argv[2])
    message = sys.argv[3]
    output_image = sys.argv[4]

    # Each pixel can store 3 bytes of data, 1 byte per channel.
    # This algorithm ignores the alpha channel, although it could
    # be used to store data in pixels more efficiently.

    # 32 bytes are needed for the AES-256 key.
    # This can be stored in 10 pixels + 2 bytes of the 11th pixel.

    # 32 bytes are needed for the HMAC key.
    # The first byte will be stored in the 11th pixel's last byte.
    # The remaining bytes are stored in the following pixels.

    # Structure:
    # AES-256 key: 32 bytes
    # HMAC key: 32 bytes
    # IV: 16 bytes
    # HMAC: 32 bytes
    # Message length after padding (encrypted): 16 bytes
    # Ciphertext: variable length, divisible by 16
    # Padding: variable length, randomly generated

    message_padded = pad(message.encode(), 16)
    bytes_available = width * height * 3
    bytes_needed = 32 + 32 + 16 + 32 + len(message_padded)
    if bytes_needed > bytes_available:
        print(
            f"Not enough pixels to store the message. Need {bytes_needed} bytes, but only {bytes_available} bytes are available.")
        sys.exit(1)

    pixel_data = encode_message(width, height, message_padded)
    image = Image.new("RGB", (width, height))
    image.putdata(pixel_data)

    image.save(output_image)
