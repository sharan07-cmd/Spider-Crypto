import argparse
import hashlib

def cipher_logic(text, shift):

    result="" 

    for l in text:

        if(l==" " or l=="," or l=="/" or l=="!" or l=="."):  ## checking for special characters
            result+=l

        elif(l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            p=ord(l)
            q=p-65                   ## subtracting 65 because we are converting the ASCII values of each letter to 1,2,3.... so that we can perform modular division by 26
            t=q+shift                ## adding the shift

            t=t%26                   ## checking if the number wraps around 26 and stays within the bound of 0-25
            t=t+65                   ## adding 65 because we can find the chr value of the ASCII value
            io=chr(t)                ## finding the character
            result+=io               ## finally adding it to the result

        elif(l in "abcdefghijklmnopqrstuvwxyz"):
            p1=ord(l)                ## getting the ASCII value
            q1=p1-97                 ## subtracting 97 because the ASCII value of a is 97 and we can use it for performing the modular arithemetic division by 26
            t1=q1+shift              ## we are adding the secret shift number

            t1=(t1)%26               ## checking if the number wraps around 26 and stays within the bound of 0-25
            t1=t1+97                 ## adding 65 because we can find the chr value of the ASCII value
            io1=chr(t1)              ## finding the character
            result+=io1              ## adding it to the result
        
    return result
#print(cipher_logic("SHARAN",3))

def read_text(filepath):             ## creating a function for copying the original text which is to be encrypted

    with open(filepath,'r') as file: ## opening the file in read mode
        text=file.read()             ## copying the content to a variable called "text"
    return text

def write_text(filepath,content):    ## creating a function for writing the encrypted content in a new file

    with open(filepath,'w') as file: ## opening the file in w mode
        file.write(content)          ## writing the content

def score_count(text):               ## creating a function for counting the number of times the high frequency letter appears in the encrypted text

    counter=0                        ## creating a variable called counter
    text=text.upper()                ## making the entire text in upper case so that there will be no confusion between upper and lower case letters
    for letter in text:
        if letter in "ETAOINSHR":    ## the high frequence letters in english are E,T,A,O,I,S,H,R. Checking if the letter is in this
            counter+=1               ## Incrementing the counter
    return counter

def crack_cipher(encrypted_text):    ## creating a funciton for doing the frequency analysis 

    leaderboard=[]

    for i in range(1,26):
        testx=cipher_logic(encrypted_text,-i)   ## we are putting -i because we need to decrypt the text through different keys from 1 to 25
        score=score_count(testx)                ## finding the number of times the high frequence letters appear in the decrypted text
        tuple1=(score,i,testx)                  ## combining all 3 of them as a tuple

        leaderboard.append(tuple1)              ## adding the tuple to the leaderboard
    leaderboard.sort()                 
    leaderboard.reverse()                       ## sorting and reversing the leaderboard list so that we will have it in the descending order

    return leaderboard[0][2],leaderboard[1][2],leaderboard[2][2]

def hash_fn(encrypted_txt,unencrypted_txt):     ## creating a function for hashing
    t=unencrypted_txt.encode()                  ## converting it to bytes
    p2=hashlib.sha256(t).hexdigest()            ## using sha256 algorithm to hash it and convert it to hex format
    sti=p2+"||"+encrypted_txt                   ## combining the encrypted text and the hash to form a single string
    return sti

def verify_fn(packaged_txt,shift):
    parts = packaged_txt.split("||")
    decrypted_txt=cipher_logic(parts[1],-shift)
    oc=decrypted_txt.encode()
    p3=hashlib.sha256(oc).hexdigest()
    if(p3==parts[0]):
        print("SUCCESS: FILE IS AUTHENTIC")
    else:
        print("FILE IS TAMPERED")
    
    return decrypted_txt

parser=argparse.ArgumentParser("A Caesar cipher text value")

parser.add_argument("action", choices=["encrypt","decrypt","crack"])     ## creating an arguement to check the CLI interface to see what we need to do
parser.add_argument("filename")                                          ## creating an arguement to parse the filename
parser.add_argument("--shift", type=int, default=3)                      ## creating an arguement to check what number should we shift the original text    
parser.add_argument("--verify", action="store_true")                     ## creating an argeument to check if the user has called the verify to create a hash or not

args=parser.parse_args()                                                 ## combining all the arguements into a list
#print(args)
 
raw_text=read_text(args.filename)                                        ## getting the original text from the file   

if(args.action=='encrypt'):                                              ## if the action provided by the user was encrypt.....
    final_text=cipher_logic(raw_text,args.shift)                         ## we are encrypting the text
    if(args.verify):
        final_text=hash_fn(final_text,raw_text)
    write_text("encrypted_"+args.filename,final_text)                    ## creating a new file as encrypted text 

elif(args.action=='decrypt'):                                            ## if the action provided by the user was decrypt.....
    if(args.verify):
        final_text=verify_fn(raw_text, args.shift)                       ## if verify is there means hash function is called and checks if the file is tampered
    else:
        final_text = cipher_logic(raw_text, -args.shift)                 ## if the verify function is not called means normal cipher_logic function is called
    

elif(args.action=='crack'):                                              ## if the action provided by the user as crack without giving the shift number
    final_text=crack_cipher(raw_text)                                    ## using the crack_cipher function to crack it

    print("\nTop 3 most likely passwords:")                              ## printing the top 3 possible cracked answers
    print("1.", final_text[0])
    print("2.", final_text[1])
    print("3.", final_text[2])

#print("OPERATION SUCCESS!!")



           