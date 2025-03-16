import sys

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad
from PIL import Image


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

    message = decode_pixel_data(pixel_data)
    print(f"Decoded message: {message}")
