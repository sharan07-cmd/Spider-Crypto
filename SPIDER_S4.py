from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import hashlib
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization

def key_gen():
    private_key=rsa.generate_private_key(public_exponent=65537, key_size= 2048)                         ## the private_key variable has all the necessary values to calculate both the private key and the public key. It acts as a briefcase containing all those
    public_key=private_key.public_key()                                                                 ## it takes only the public quotient values and the two primes(multiply the two primes) from the private key suitcase

    with open("private.pem",'wb') as file:                                                              ## opening a privatee.pem file in write bytes mode
        file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,                       ## this tells in which form the output data should be stored in the pem file(it uses base64 and dumps the binary data in english in the file)
                                             format=serialization.PrivateFormat.TraditionalOpenSSL,     ## this tells in which way the mathematical data should be arranged in the file    
                                             encryption_algorithm=serialization.NoEncryption()))        ## this tells that no encryption is required for the private.pem file

    with open("public.pem",'wb') as file:
        file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,                         ## this tells that in what way the output data should be presented, that is in eiher english using base64 or raw binary data
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo))     ## this line tells how to format the public key
    
    print("SUCCESS: RSA Keypair generated and saved!")


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

def encrypt_file(filepath):                                                          ## creating a function for getting the data from the files in the form of bytes and passing it through the encryption engine
    
    with open(filepath,'rb') as file:
        file_bytes=file.read()                                                       ## creating a variable and putting the data from the file in the bytes format

    aes_key=os.urandom(32)                                                           ## generating a random 32 byte key for aes
    iv=os.urandom(16)                                                                ## randomly generating a 16 byte iv
    salt=os.urandom(16)                                                              ## randomly generating a 16 byte salt
    
    ciphertext=aesencrypt(file_bytes,aes_key,iv)                                     ## getting the cipher text by passing the data(in bytes), key and the iv through the encryption engine

    hash1=hashlib.sha256(file_bytes).digest()                                        ## calculating the hash of the original data

    with open("public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    rsa_encrypted_aes_key = public_key.encrypt(                                      ## encrypting the AES key using the RSA algorithm   
        aes_key,
        padding=rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    total = rsa_encrypted_aes_key + iv + salt + hash1 + ciphertext                    ## combining all the 4 byte values(salt, iv, hash1 and ciphertext) 
    
    with open(filepath+".enc",'wb') as file:
        file.write(total)                                                             ## putting the combined string in the enccrypted file output


def decrypt_file(filepath):                                                           ## creating a function for the decryption function of the file

    with open(filepath+".enc", 'rb') as file:
        total1=file.read()                                                            ## collecting the encrypted data and putting into a variable

    encaes_key=total1[:256]                                                                ## slicing the encrypted aes key using RSA algorithm
    iv=total1[256:272]                                                                     ## slicing the 16 byte iv 
    salt=total1[272:288]                                                                   ## slicing the 16 byte salt
    hash1=total1[288:320]                                                                  ## slicing the 32 byte hash of the original text
    ciphertext=total1[320:]                                                                ## slicing the ciphertext

    with open("private.pem",'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    aes_key = private_key.decrypt(
        encaes_key,
        padding=rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    real_text=aesdescrypt(ciphertext,aes_key,iv)                                       ## passing the cipher text, the iv and the key which we obtained in the previous steps through the decryption funciton
    new_hash=hashlib.sha256(real_text).digest()                                        ## calculating the hash of the text which we decrypted in the previous step

    if(new_hash==hash1):                                                               ## checking if the hashes are equal
        print("THE FILE IS NOT CORRUPTED")
    elif(new_hash!=hash1):
        print("THE FILE IS TAMPERED")
        return                                                                         ## does not return the corrupted output as we know that the file has been tampered
        

    with open(filepath,'wb') as file:                                                  ## if the hashes are equal means the output bytes are then entered in a file
        file.write(real_text)


parser=argparse.ArgumentParser()
parser.add_argument("action", choices=["encrypt","decrypt","keygen"])                  ## creating an arguement to check the CLI interface to see what we need to do
parser.add_argument("filename",nargs="?")                                              ## creating an arguement to parse the filename

args=parser.parse_args()                                                               ## creating a namespace consisting of all the parse arguements

if (args.action=="encrypt"):                                                           ## if the action provided by the user is encrypt....
    if args.filename:
        encrypt_file(args.filename)                                                    ## calling the encrypt function to encrypt the file
    else:
        print("ERROR: You must provide a filename to encrypt!")
        
elif (args.action=='decrypt'):                                                         ## if the action provided by the user is decrypt....
    if args.filename:
        decrypt_file(args.filename)                                                    ## calling the decrypt function to decrypt the file
    else:
        print("ERROR: You must provide a filename to decrypt!")

elif (args.action=="keygen"):                                                          ## if the action provided by the user is keygen
    key_gen()                                                                          ## generation of public and private keys are done
