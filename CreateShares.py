from decimal import *
import tss
import random
from Crypto.Cipher import AES
from Crypto import Random
import base64

def encryptandshare(p,m,keys):

    #Create the shares
    shares =(tss.share_secret(m,(2*m),p,'',tss.Hash.SHA256))
    #Create instruction table file
    file = open('InstructionTable.txt', 'w')

    #Padding to ensure the key length is a multiple of 16 bytes (as required by AES)
    length = 16 - (len(keys) % 16)
    keys += chr(length) * length

    #Encrypt the shares
    for i in range(0,2*m):
        iv = Random.new().read(AES.block_size)
        encryption_suite = AES.new(keys, AES.MODE_CFB , iv)
        cipher_text0 = iv+(encryption_suite.encrypt(shares[i]))
        cipher = base64.b64encode(cipher_text0)
        file.write(cipher+' ')
        if(i%2==1):
            file.write('\n')
    file.close()



def generatehpwd(m):
    q=626436561503166578967805515819693654293211766937 #binary 160 bits Prime No.- 0110110110111010011000110000110111111101001000000111110001110100100010110110000000011101110011000100001111101110000110000101001100001101100110111110000010011001
    p=Decimal(random.random()*q) #Generate a Random hardened password
    print (p)
    return p


def createhistoryfile(keys,h,m):
    keys=str(keys)[0:32]
    print(keys) #32 byte key from Hpwd to encrypt history file; AES needs only 32 bytes
    keys=keys.encode()

    #Create the history file
    print ('History file size would be '+str(m)+' X '+str(h))
    a='000' #dummy content on the initialized history file
    s=0
    file=open('History.txt','w') #Create History File and encrypt dummy history file contents with hardened password
    for i in range(0,h):
        for i in range(0,m):
            iv = Random.new().read(AES.block_size)
            encryption_suite = AES.new(keys, AES.MODE_CFB, iv)
            cipher_text0 = iv + encryption_suite.encrypt(a)
            cipher=base64.b64encode(cipher_text0)
            file.write(cipher+' ')

        file.write('\n')
    file.close()



password = raw_input("Enter correct user password for initialisation\n")   # taking correct password as a input from user, to compute number of feature values
m=len(password)-1       #calculating number of feature values based on password's length
getcontext().prec = 10000
h=5 #size of history file
keys=password
p=generatehpwd(m)
encryptandshare(p,m,keys)
createhistoryfile(p,h,m)
