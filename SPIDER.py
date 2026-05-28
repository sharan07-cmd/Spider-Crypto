import argparse

def cipher_logic(text, shift):

    result="" 
    for l in text:
        if(l==" " or l=="," or l=="/" or l=="!" or l=="."):
            result+=l
        elif(l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            p=ord(l)
            q=p-65
            t=q+shift
            t=t%26
            t=t+65
            io=chr(t)
            result+=io
        elif(l in "abcdefghijklmnopqrstuvwxyz"):
            p1=ord(l)
            q1=p1-97
            t1=q1+shift
            t1=(t1)%26
            t1=t1+97
            io1=chr(t1)
            result+=io1
        
    return result
#print(cipher_logic("SHARAN",3))

def read_text(filepath):

    with open(filepath,'r') as file:
        text=file.read()
    return text

def write_text(filepath,content):

    with open(filepath,'w') as file:
        file.write(content)

def score_count(text):

    counter=0
    text=text.upper()
    for letter in text:
        if letter in "ETAOINSHR":
            counter+=1
    return counter

def crack_cipher(encrypted_text):

    leaderboard=[]
    for i in range(1,26):
        testx=cipher_logic(encrypted_text,-i)
        score=score_count(testx)
        tuple1=(score,i,testx)
        leaderboard.append(tuple1)
    leaderboard.sort()
    leaderboard.reverse()
    return leaderboard[0][2],leaderboard[1][2],leaderboard[2][2]

parser=argparse.ArgumentParser("A Caesar cipher text value")

parser.add_argument("action", choices=["encrypt","decrypt","crack"])
parser.add_argument("filename")
parser.add_argument("--shift", type=int, default=3)

args=parser.parse_args()
#print(args)

raw_text=read_text(args.filename)

if(args.action=='encrypt'):
    final_text=cipher_logic(raw_text,args.shift)
    write_text("encrypted_"+args.filename,final_text)

elif(args.action=='decrypt'):
    final_text=cipher_logic(raw_text,-args.shift)
    write_text("decrypted_"+args.filename,final_text)

elif(args.action=='crack'):
    final_text=crack_cipher(raw_text)

    print("\nTop 3 most likely passwords:")
    print("1.", final_text[0])
    print("2.", final_text[1])
    print("3.", final_text[2])

#print("OPERATION SUCCESS!!")



           