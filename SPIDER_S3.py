from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding

def key_der(password,salt):
    t=password.encode()
    p=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=500000)
    key=p.derive(t)

    return key

def aesencrypt(databytes,key,iv):
    padder=padding.PKCS7(128).padder()
    padded_data=padder.update(databytes)+padder.finalize()
    cipher=cipher(algorithms.AES(key),modes.CBC(iv))
    encryptor=cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aesdescrypt(ciphertext,key,iv):
    cipher=Cipher(algorithms.AES(key),modes.CBC(iv))
    decryptor= cipher.decryptor()
    padded_data=decryptor.update(ciphertext)+decryptor.finalize()
    unpadder=padding.PKCS7(128).unpadder()
    original_text=unpadder.update(padded_data)+unpadder.finalize()
    return original_text