import sys
from collections import Counter

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad
from PIL import Image


def determine_colour_size(width, _height, pixel_data):
    first_row = pixel_data[:width]
    num_sames = []
    num_same = 1
    for pixel, prev_pixel in zip(first_row[1:], first_row):
        if pixel == prev_pixel:
            num_same += 1
            continue
        num_sames.append(num_same)
        num_same = 1
    return Counter(num_sames).most_common(1)[0][0]


def scale_down_pixel_data(width, height, pixel_data):
    colour_size = determine_colour_size(width, height, pixel_data)
    pixel_data_2d = [pixel_data[i:i + width]
                     for i in range(0, len(pixel_data), width)]

    new_pixel_data_2d = []
    for i in range(0, len(pixel_data_2d), colour_size):
        row = pixel_data_2d[i]
        new_row = []
        for j in range(0, len(row), colour_size):
            new_row.append(row[j])
            if len(new_row) == width // colour_size:
                break
        new_pixel_data_2d.append(new_row)
        if len(new_pixel_data_2d) == height // colour_size:
            break

    new_pixel_data = [pixel for row in new_pixel_data_2d for pixel in row]
    return new_pixel_data


def decode_pixel_data(pixel_data):
    data = b"".join([bytes(pixel) for pixel in pixel_data])

    aes_key = data[:32]
    hmac_key = data[32:64]
    iv = data[64:80]
    mac = data[80:112]
    message_length_encrypted = data[112:128]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    message_length_bytes = unpad(cipher.decrypt(message_length_encrypted), 16)
    message_length = int.from_bytes(message_length_bytes)
    ciphertext = data[128:128 + message_length]

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(iv + message_length_encrypted + ciphertext)
    try:
        hmac.verify(mac)
    except ValueError:
        raise ValueError("MAC mismatch")

    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext.decode()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <image_path>" % sys.argv[0])
        sys.exit(1)

    image_path = sys.argv[1]
    image = Image.open(image_path)
    pixel_data = list(image.getdata())

    width, height = image.size
    pixel_data = scale_down_pixel_data(width, height, pixel_data)
    message = decode_pixel_data(pixel_data)
    print(f"Decoded message: {message}")
