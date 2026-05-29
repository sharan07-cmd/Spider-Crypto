from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding

import os
import hashlib

import argparse

def key_der(password,salt):                                                          ## creating a function to add salt to the end of the password and scramble to make it to 32 bytes

    t=password.encode()                                                              ## converting the string to bytes
    p=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=500000)    ## calling the PBKDF2HMAC algorithm to add the salt to the end of the password, make it to the length of 32 and scramble it for 500000 times
    key=p.derive(t)                                                                  ## passing the password bytes through the algorithm

    return key 

def aesencrypt(databytes,key,iv):                                                    ## creating a function for encryption using AES in CBC mode

    padder=padding.PKCS7(128).padder()                                               ## calling the PKCS7 algorithm so that padding can be done
    padded_data=padder.update(databytes)+padder.finalize()                           ## making the data multiple of 16 bytes so that it can be passed through the AES
    cipher=Cipher(algorithms.AES(key),modes.CBC(iv))                                 ## calling the AES in CBC mode
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

def encrypt_file(filepath,password):                                   ## creating a function for getting the data from the files in the form of bytes and passing it through the encryption engine
    with open(filepath,'rb') as file:
        file_bytes=file.read()                                         ## creating a variable and putting the data from the file in the bytes format
        iv=os.urandom(16)                                              ## randomly generating a 16 byte iv
        salt=os.urandom(16)                                            ## randomly generating a 16 byte salt
        t=key_der(password,salt)                                       ## getting the primary key by passing the password and salt through the key deriving function
        
        ciphertext=aesencrypt(file_bytes,t,iv)                         ## getting the cipher text by passing the data(in bytes), key and the iv through the encryption engine

        hash1=hashlib.sha256(file_bytes).digest()                      ## calculating the hash of the original data
        total=salt+iv+hash1+ciphertext                                 ## combining all the 4 byte values(salt, iv, hash1 and ciphertext) 
    
    with open(filepath+".enc",'wb') as file:
        file.write(total)                                              ## putting the combined string in the enccrypted file output


def decrypt_file(filepath,password):                                   ## creating a function for the decryption function of the file

    with open(filepath+".enc", 'rb') as file:
        total1=file.read()                                             ## collecting the encrypted data and putting into a variable
        salt=total1[:16]                                               ## getting the salt using string splicing(here 0-15 because salt is a 16 byte value)
        iv=total1[16:32]                                               ## getting the iv using string splicing (here 16-31 because the iv is also a 16 byte value)                                              
        hash1=total1[32:64]                                            ## getting the hash using string splicing (here 32-63 because we computed hash using sha256 algorithm which creates a 32 byte hash)
        ciphertext=total1[64:]                                         ## getting the cipher text till the end of the file using the string splicing

        ipi=key_der(password,salt)                                     ## getting the key using the password we know and the salt which we obtained in the previous step
        real_text=aesdescrypt(ciphertext,ipi,iv)                       ## passing the cipher text, the iv and the key which we obtained in the previous steps through the decryption funciton
        new_hash=hashlib.sha256(real_text).digest()                    ## calculating the hash of the text which we decrypted in the previous step

        if(new_hash==hash1):                                           ## checking if the hashes are equal
            print("THE FILE IS NOT CORRUPTED")
        elif(new_hash!=hash1):
            print("THE FILE IS TAMPERED")
            return                                                     ## does not return the corrupted output as we know that the file has been tampered
    
    with open(filepath,'wb') as file:                                  ## if the hashes are equal means the output bytes are then entered in a file
        file.write(real_text)

parser=argparse.ArgumentParser()
parser.add_argument("action", choices=["encrypt","decrypt"])             ## creating an arguement to check the CLI interface to see what we need to do
parser.add_argument("filename")                                          ## creating an arguement to parse the filename

args=parser.parse_args()                                                 ## creating a namespace consisting of all the parse arguements

if (args.action=="encrypt"):                                             ## if the action provided by the user is encrypt....
    password=input("Enter the password of your vault: ")                 ## getting the password from the user
    ciphertext=encrypt_file(args.filename,password)                      ## calling the encrytpion function and finding the ciphertext

elif (args.action=='decrypt'):                                           ## if the action provided by the user is decrypt....
    password=input("Enter the password of your vault: ")                 ## getting the password from the user
    output_file=decrypt_file(args.filename,password)                     ## getting the output file.