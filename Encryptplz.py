from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

def password_protect_file(file_path, password):
    
##################################################################

#   Generate a salt for password
    
##################################################################

    salt = os.urandom(16)

##################################################################

#   Generate a key from the password, does it function? let's find out.

################################################################## 

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    
################################################################## 

#   Can only use kdf once.
 
################################################################## 

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
##################################################################

#   Create a Fernet cipher object with the key, black magic ensues

################################################################## 

    cipher = Fernet(key)


##################################################################

#   Read file content

################################################################## 


    with open(file_path, 'rb') as file:
        file_content = file.read()
        
##################################################################

#   Encrypt file content/ Create oogabooga 
    
################################################################## 



    encrypted_content = cipher.encrypt(file_content)
    
    
################################################################## 

#   Write encrypted content back to the file 
    
################################################################## 
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)
        

################################################################## 
#
#   Save the encryption key to a separate file
#   
#   Separate key from salt w/ NL
#   
################################################################## 



    key_file_path = file_path + ".key"
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)
        key_file.write(b'\n') 
        key_file.write(salt)


################################################################## 

#   Remove the original file, for science
    
################################################################## 

    os.remove(file_path)

    print("File successfully password protected as:", encrypted_file_path)
    print("Encryption key saved to:", key_file_path)
    

################################################################## 

#   FP goes here , im sure there's a better way to read this.

file_path = "C:/Users/User/Desktop/Name.zip"  

################################################################## 


password = "" 

#       password, obviously.

################################################################## 

password_protect_file(file_path, password)
