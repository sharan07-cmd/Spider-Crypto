from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding

def key_der(password,salt):                                                          ## creating a function to add salt to the end of the password and scramble to make it to 32 bytes

    t=password.encode()                                                              ## converting the string to bytes
    p=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=500000)    ## calling the PBKDF2HMAC algorithm to add the salt to the end of the password, make it to the length of 32 and scramble it for 500000 times
    key=p.derive(t)                                                                  ## passing the password bytes through the algorithm

    return key 

def aesencrypt(databytes,key,iv):                                                    ## creating a function for encryption using AES in CBC mode

    padder=padding.PKCS7(128).padder()                                               ## calling the PKCS7 algorithm so that padding can be done
    padded_data=padder.update(databytes)+padder.finalize()                           ## making the data multiple of 16 bytes so that it can be passed through the AES
    cipher=cipher(algorithms.AES(key),modes.CBC(iv))                                 ## calling the AES in CBC mode
    encryptor=cipher.encryptor()                                                     ## Setting the AES to encryptor mode 
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()                ## passing the padded data through the AES ENCRYPTOR engine

    return ciphertext

def aesdescrypt(ciphertext,key,iv):                                                  ## creating a funciton for decryption using AES in CBC mode

    cipher=Cipher(algorithms.AES(key),modes.CBC(iv))                                 ## calling the AES algorithm in CBC mode and passing the key and iv through it
    decryptor= cipher.decryptor()                                                    ## setting it in decryption mode
    padded_data=decryptor.update(ciphertext)+decryptor.finalize()                    ## passing the ciphertext through the decryption engine
    unpadder=padding.PKCS7(128).unpadder()                                           ## Unpadding should be done to get the original text. So we are calling the PKCS7 algorithm in unpadding mode
    original_text=unpadder.update(padded_data)+unpadder.finalize()                   ## passing the text with the padding

    return original_text