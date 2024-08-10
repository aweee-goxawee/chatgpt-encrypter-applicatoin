from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def pad_key(key: str) -> bytes:
    """Pads the key to 16 bytes (128 bits) if it's shorter, or truncates it if longer."""
    return (key.encode() + b'\0' * 16)[:16]

def encrypt(plaintext: str, password: str) -> str:
    """Encrypts plaintext using AES-GCM."""
    key = pad_key(password)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return (iv + encryptor.tag + ciphertext).hex()

def decrypt(ciphertext_hex: str, password: str) -> str:
    """Decrypts ciphertext using AES-GCM."""
    raw_data = bytes.fromhex(ciphertext_hex)
    iv = raw_data[:12]
    tag = raw_data[12:28]  
    actual_ciphertext = raw_data[28:]

    key = pad_key(password)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    option = input("Enter 'encrypt' to encrypt or 'decrypt' to decrypt: ").strip().lower()
    password = input("Enter the password: ").strip()

    if option == "encrypt":
        plaintext = input("Enter the text to encrypt: ").strip()
        encrypted = encrypt(plaintext, password)
        print(f"Encrypted (hex): {encrypted}")
    elif option == "decrypt":
        ciphertext = input("Enter the hex-encoded text to decrypt: ").strip()
        try:
            decrypted = decrypt(ciphertext, password)
            print(f"Decrypted: {decrypted}")
        except Exception as e:
            print(f"Failed to decrypt: {e}")
    else:
        print("Invalid option. Please enter 'encrypt' or 'decrypt'.")
