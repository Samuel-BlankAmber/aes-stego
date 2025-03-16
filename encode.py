import sys
import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
from PIL import Image


def nearest_neighbour_upscale(pixel_data, width, height, scale):
    pixel_data_2d = [pixel_data[i:i + width // scale]
                     for i in range(0, len(pixel_data), width // scale)]

    new_pixel_data_2d = []
    for row in pixel_data_2d:
        new_row = []
        for pixel in row:
            new_row += [pixel] * scale
        if len(new_row) < width:
            new_row += [row[-1] for _ in range(width - len(new_row))]
        new_pixel_data_2d += [new_row] * scale
    if len(new_pixel_data_2d) < height:
        new_pixel_data_2d += [new_pixel_data_2d[-1]
                              for _ in range(height - len(new_pixel_data_2d))]

    new_pixel_data = [pixel for row in new_pixel_data_2d for pixel in row]
    return new_pixel_data


def encode_message(width, height, colour_size, padded_message):
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

    data_length = (width // colour_size) * (height // colour_size) * 3

    data = aes_key + hmac_key + iv + mac + message_length_encrypted + ciphertext
    data += b"\x00" * (len(data) % 3)
    extra_data_needed = data_length - len(data)
    data += os.urandom(extra_data_needed)

    pixel_data = [tuple(data[i:i + 3]) for i in range(0, len(data), 3)]
    if colour_size > 1:
        pixel_data = nearest_neighbour_upscale(
            pixel_data, width, height, colour_size)
    return pixel_data


if __name__ == "__main__":
    if len(sys.argv) != 5 and len(sys.argv) != 6:
        print("Usage: %s <width> <height> <message> <output_image> [colour_size]" %
              sys.argv[0])
        sys.exit(1)

    width = int(sys.argv[1])
    height = int(sys.argv[2])
    message = sys.argv[3]
    output_image = sys.argv[4]
    colour_size = 1 if len(sys.argv) == 5 else int(sys.argv[5])

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
    bytes_available = (width // colour_size) * (height // colour_size) * 3
    bytes_needed = 32 + 32 + 16 + 32 + len(message_padded)
    if bytes_needed > bytes_available:
        print(
            f"Not enough pixels to store the message. Need {bytes_needed} bytes, but only {bytes_available} bytes are available.")
        sys.exit(1)

    pixel_data = encode_message(width, height, colour_size, message_padded)
    image = Image.new("RGB", (width, height))
    image.putdata(pixel_data)

    image.save(output_image)
