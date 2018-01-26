#This file only validates the history file encryption by decrypting the initialized file
# and outputing the decrypted contents onto DecryptedHistory.txt
import base64
import random
from Crypto.Cipher import AES
from Crypto import Random

with open('History.txt', 'r') as ins:
    keys=55053707345665266990161689503130
    keys = str(keys)[0:32]
    print(keys)
    keys = keys.encode()
    file = open('DecryptedHistory.txt', 'w')

    for line in ins:
        line=line.strip()
        words = line.split(' ')
        print (len(words))
        for i in range(0,len(words)):
            word=words[i]
            cipher_text0=base64.b64decode(word)
            iv = cipher_text0[:AES.block_size]
            decryption_suite = AES.new(keys, AES.MODE_CFB, iv)
            plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])
            file.write(plain_text0+' ')
        file.write ('\n')
    file.close()