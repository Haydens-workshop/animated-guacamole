from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

def password_protect_file(file_path, password):
    ###########################################################
    # Generate salt and key
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    ###########################################################
    # Create a Fernet cipher object with the key and read file content
    cipher = Fernet(key)

    with open(file_path, 'rb') as file:
        file_content = file.read()
        
    ###########################################################
    # Bop it!
    encrypted_content = cipher.encrypt(file_content)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    ###########################################################
    # Save the encryption key and salt to a separate file
    key_file_path = file_path + ".key"
    with open(key_file_path, 'wb') as key_file:
        key_file.write(salt + b'\n' + key)

    ###########################################################
    # Remove the original file
    os.remove(file_path)

    print("File successfully password protected as:", encrypted_file_path)
    print("Encryption key and salt saved to:", key_file_path)
    
    #Update with actual file path, could create a UI for this actually
    ###########################################################
file_path = "path/to/your/file" 
password = "your_password_here"  
password_protect_file(file_path, password)
