from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
from pathlib import Path

def generate_key(password: str, salt: bytes) -> bytes:
    # Generate salt and key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=150000,  # Increased iterations for enhanced security
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: Path, key: bytes) -> bytes:
    # Create a Fernet cipher object with the key and read file content
    cipher = Fernet(key)
    with file_path.open('rb') as file:
        return cipher.encrypt(file.read())

def save_encrypted_file(file_path: Path, encrypted_content: bytes):
    # Bop it!
    encrypted_file_path = file_path.with_suffix(file_path.suffix + '.enc')
    with encrypted_file_path.open('wb') as encrypted_file:
        encrypted_file.write(encrypted_content)
    return encrypted_file_path

def save_key_and_salt(file_path: Path, key: bytes, salt: bytes):
    # Save the encryption key and salt to a separate file
    key_file_path = file_path.with_suffix('.key')
    with key_file_path.open('wb') as key_file:
        key_file.write(salt + b'\n' + key)
    return key_file_path

def password_protect_file(file_path_str: str, password: str):
    try:
        file_path = Path(file_path_str)
        salt = os.urandom(16)
        key = generate_key(password, salt)
        encrypted_content = encrypt_file(file_path, key)
        encrypted_file_path = save_encrypted_file(file_path, encrypted_content)
        key_file_path = save_key_and_salt(file_path, key, salt)
        
        # Remove the original file
        file_path.unlink()

        print(f"File successfully password protected as: {encrypted_file_path}")
        print(f"Encryption key and salt saved to: {key_file_path}")
    except Exception as e:
        print(f"Error password protecting file: {e}")

# Example usage
file_path = "path/to/your/file"
password = "your_password_here"
password_protect_file(file_path, password)
