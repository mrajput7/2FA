#Validate Created Instruction Table

import base64
import random
from Crypto.Cipher import AES
from decimal import *
import tss


getcontext().prec = 10000
m=4
counter=0
DecryptedInstructionTable = [[0 for x in range(2)] for y in range(m)]
keys='mohit'
#Padding to ensure the key length is a multiple of 16 bytes (as required by AES)
length = 16 - (len(keys) % 16)
keys += chr(length) * length
keys = keys.encode()
file = open('DecryptedInstruction.txt', 'w')
with open('InstructionTable.txt', 'r') as ins:
    for line in ins:
        words = line.split(' ')
        words[0]=words[0].strip()
        words[1]=words[1].strip()

        #Decrypt fast column entry
        word=words[0]
        cipher_text0 = base64.b64decode(word)
        iv = cipher_text0[:AES.block_size]
        decryption_suite = AES.new(keys, AES.MODE_CFB, iv)
        plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])

        #Decrypt slow column entry
        word = words[1]
        cipher_text0 = base64.b64decode(word)
        iv = cipher_text0[:AES.block_size]
        decryption_suite = AES.new(keys, AES.MODE_CFB, iv)
        plain_text1 = decryption_suite.decrypt(cipher_text0[AES.block_size:])

        DecryptedInstructionTable[counter][0]=plain_text0
        DecryptedInstructionTable[counter][1]=plain_text1

        counter=counter+1
w = list()
for i in range(0, m+1):  # Atleast m shares required to reconstruct the secret
    w.append(DecryptedInstructionTable[i / 2][i % 2])

#Reconstruct the secret
secret = Decimal(tss.reconstruct_secret(w))
print(Decimal(secret))




