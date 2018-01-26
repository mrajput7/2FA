from decimal import *
import tss
import random
import io
import base64
import rstr
import numpy as np
import sys
from Crypto.Cipher import AES
from Crypto import Random
from decimal import *

t = 10  # given threshold value (ti) to be taken as 10
k = 2  # given kappa value
h = 5  # given history file only contains 5 recent successful attempts.

# Creating initial hardenpassword by taking any m shares which are created in 'CreateShares.py'
def initial_hdpwd(pwd):
    shares = list()  # defining a empty list which can store decrypted shares
    length = 16 - (len(pwd) % 16)  # Key padding
    pwd += chr(length) * length
    pwd = pwd.encode()
    with open('InstructionTable.txt', 'r') as ins:
        for line in ins:
            words = line.split(' ')
            encrypted_share = words[0]
            cipher_text0 = base64.b64decode(encrypted_share)
            iv = cipher_text0[:AES.block_size]
            decryption_suite = AES.new(pwd, AES.MODE_CFB, iv)
            plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])
            shares.append(plain_text0)
        first_hdpwd = (tss.reconstruct_secret(shares))  # reconstructing harden password from m shares
        first_hdpwd = first_hdpwd[0:32] # only taking first 32 digit as AES use keys in multiples of 16
        return Decimal(first_hdpwd) # returning harden password
    ins.close()


# updating history file for first 5 genuine login attempt
def history(feature_val, hdpwd):
    hdpwd = str(hdpwd)[0:32] # padding
    hdpwd = hdpwd.encode()
    shares_history = list() # creating a list datatype to store
    temp_array = list()
# encrypting feature value
    for i in range(0, m):
        iv = Random.new().read(AES.block_size)
        encryption_suite = AES.new(hdpwd, AES.MODE_CFB, iv)
        cipher_text0 = iv + encryption_suite.encrypt(str(feature_val[i]))
        cipher = base64.b64encode(cipher_text0)
        shares_history.append(cipher)

    file = open('History.txt', 'r') # Opening History file to read its contents
    lines = file.readlines()
    lines = lines[:-1]              #deleting last entry (oldest entry), to make room for new entry
    lines = ''.join(lines)
    file.close()                    # Closing History file after read operation
    s = ''
    for i in shares_history:
        s = s + i + ' '
    file = open('History.txt', 'w') # Opening History fie for writing
    file.write(s + "\n" + lines )   # Writing  new feature value
    file.close()


# Updating history file after every successful login

def update_history(feature_val,hdpwd,hard_pwd):
    hdpwd = str(hdpwd)[0:32]   #padding
    hdpwd = hdpwd.encode()
    hard_pwd = str(hard_pwd)[0:32]  #padding
    hard_pwd = hard_pwd.encode()
    shares_history = list()
    temp_array = list()
    d_history=list()

    with open('History.txt', 'r') as ins:
        for line in ins:
            line = line.strip()
            words = line.split(' ')
            for i in range(0, len(words)):
                word = words[i]
                cipher_text0 = base64.b64decode(word)
                iv = cipher_text0[:AES.block_size]
                decryption_suite = AES.new(hdpwd, AES.MODE_CFB, iv)
                plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])
                temp_array.append(plain_text0)
            d_history.append(temp_array)
            temp_array = list()      #storing decrypted history context to temp

    ins.close()
#encrypting history file with new hardened password
    file=open('History.txt','w')
    for i in range(0,h):
        for j in range(0,m):
            iv = Random.new().read(AES.block_size)
            encryption_suite = AES.new(hard_pwd, AES.MODE_CFB, iv)
            cipher_text0 = iv + encryption_suite.encrypt(d_history[i][j])
            cipher=base64.b64encode(cipher_text0)
            file.write(cipher+' ')
        file.write('\n')
    file.close()
# storing latest value of feature vector
    for i in range(0, m):
        iv = Random.new().read(AES.block_size)
        encryption_suite = AES.new(hard_pwd, AES.MODE_CFB, iv)
        cipher_text0 = iv + encryption_suite.encrypt(str(feature_val[i]))
        cipher = base64.b64encode(cipher_text0)
        shares_history.append(cipher)

    file = open('History.txt', 'r')
    lines = file.readlines()
    lines = lines[:-1]         # deleting last row to update it with the latest value of feature vector
    lines = ''.join(lines)
    file.close()
    s = ''
    for i in shares_history:
        s = s + i + ' '
    file = open('History.txt', 'w') # opening history file
    file.write(s + "\n" + lines )
    file.close()                    # closing history file



# updating instruction file, on the basis of new mean and standard mediation
def create_inst_table(password, hpwd):
    password = password.strip('\n')
    flag = list()
    u_mean = mean(hpwd)             # calculating mean by calling mean function
    std = standard_deviation(hpwd)  # calculating standard_deviation by calling standard_deviation function
    q = 626436561503166578967805515819693654293211766937  # binary 160 bits Prime No.- 0110110110111010011000110000110111111101001000000111110001110100100010110110000000011101110011000100001111101110000110000101001100001101100110111110000010011001
    hard_pwd = Decimal(random.random() * q)  # Generate a Random hardened password after each successful login attempt
    hard_pwd = str(hard_pwd)[0:32]         #padding
    hard_pwd = int(hard_pwd)
    shares = (tss.share_secret(m, (2 * m), hard_pwd, '', tss.Hash.SHA256))  # defining that m shares are needed from 2m shares to sucessfully create hard_pwd
    update_history(feature_val,hpwd,hard_pwd)              # calling update_history function
    file = open('InstructionTable.txt', 'w')               # opening InstructionTable file
    file.truncate()                                        # deleting previous entries from file
    length = 16 - (len(password) % 16)                     # Padding to ensure the key length is a multiple of 16 bytes (as required by AES)
    password += chr(length) * length
    for i in range(0, m):
        if (u_mean[i] + (k * std[i])) < t:                 # checking conditions to choose where the user is fast or slow for ith feature, here features are taken from zero as i start from 0.
            flag.append(0)
        elif (u_mean[i] - (k * std[i])) > t:
            flag.append(1)
        else:
            flag.append(-1)
    for i in range(0, m):                                  # encrypting m shares from password and storing according its place in instruction table,i.e left or right
        if (flag[i] == 0):
            iv = Random.new().read(AES.block_size)
            encryption_suite = AES.new(password, AES.MODE_CFB, iv)
            cipher_text0 = iv + (encryption_suite.encrypt(shares[2 * i]))  # creating correct share and storing it to left column of instruction table
            cipher = base64.b64encode(cipher_text0)
            file.write(cipher + ' ')
            iv = Random.new().read(AES.block_size)
            keyrand = str(rstr.digits(5))
            length = 16 - (len(keyrand) % 16)
            keyrand += chr(length) * length
            encryption_suite = AES.new(keyrand, AES.MODE_CFB, iv)
            cipher_text0 = iv + (encryption_suite.encrypt(shares[(2 * i) + 1]))  # creating random vague share and storing it to right column of instruction table
            cipher = base64.b64encode(cipher_text0)
            file.write(cipher + ' ')
            file.write('\n')
        if (flag[i] == 1):
            iv = Random.new().read(AES.block_size)
            keyrand = str(rstr.digits(5))
            length = 16 - (len(keyrand) % 16)
            keyrand += chr(length) * length
            encryption_suite = AES.new(keyrand, AES.MODE_CFB, iv)
            cipher_text0 = iv + (encryption_suite.encrypt(shares[2 * i]))  # creating random vague share and storing it to left column of instruction table
            cipher = base64.b64encode(cipher_text0)
            file.write(cipher + ' ')
            iv = Random.new().read(AES.block_size)
            encryption_suite = AES.new(password, AES.MODE_CFB, iv)
            cipher_text0 = iv + (encryption_suite.encrypt(shares[(2 * i) + 1]))  # creating correct share and storing it to right column of instruction table
            cipher = base64.b64encode(cipher_text0)
            file.write(cipher + ' ')
            file.write('\n')
        if (flag[i] == -1):
            iv = Random.new().read(AES.block_size)
            iv = Random.new().read(AES.block_size)
            encryption_suite = AES.new(password, AES.MODE_CFB, iv)
            cipher_text0 = iv + (encryption_suite.encrypt(shares[2 * i]))     # creating correct share and storing it to left column of instruction table
            cipher = base64.b64encode(cipher_text0)
            file.write(cipher + ' ')
            iv = Random.new().read(AES.block_size)
            encryption_suite = AES.new(password, AES.MODE_CFB, iv)
            cipher_text0 = iv + (encryption_suite.encrypt(shares[(2 * i) + 1]))  # creating correct share and storing it to right column of instruction table
            cipher = base64.b64encode(cipher_text0)
            file.write(cipher + ' ')
            file.write('\n')                                                     # closing  InstructionTable after updating file
    file.close()


# Decrypting cipher text which are provided by mean and standard deviation function for calculating mean and standard deviation
def decryption_hpwd(word, hdpwd):
    hdpwd = str(hdpwd)               #padding
    hdpwd = hdpwd.encode()
    cipher_text0 = base64.b64decode(word)
    iv = cipher_text0[:AES.block_size]
    decryption_suite = AES.new(hdpwd, AES.MODE_CFB, iv)
    plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])
    return plain_text0


# calculating mean
def mean(keys):
    keys = Decimal(keys)
    arr = list()
    mean_list = list()
    counter = 0
    with open('History.txt', 'r') as ins:         # Open History file for reading
        for line in ins:
            line = line.strip()
            words = line.split(' ')
            counter = counter + 1
            if counter == 6:                      # Reading only 5 rows of history file
                break
            for i in range(0, len(words)):
                word = words[i]
                plain = int(decryption_hpwd(word, keys)) # Decrypting history file for  calculating mean
                arr.append(plain)
            mean_list.append(arr)   # storing decrypted features values into list
            arr = list()
    ins.close()                     # Closing History file
    return np.mean(mean_list, axis=0) # returning mean


# calculating standard deviation
def standard_deviation(keys):
    arr = []
    std_list = list()
    counter = 0
    with open('History.txt', 'r') as ins:         # Open History file for reading
        for line in ins:
            line = line.strip()
            words = line.split(' ')
            counter = counter + 1
            if counter == 6:                      # Reading only 5 rows of history file
                break
            for i in range(0, len(words)):
                word = words[i]
                plain = int(decryption_hpwd(word, keys))  # Decrypting history file for  calculating standar deviation
                arr.append(plain)
            std_list.append(arr)                           # storing decrypted features values into list
            arr = list()
    ins.close()                                         # Closing History file
    return np.std(std_list, axis=0)                        # returning mean


# picking up 'm'shares and using them calculating harden password, that will be use to decrypt history file for updation
def reconstruct_shares(feature_val, pwd):
    ctr = -1
    shares = list()
    length = 16 - (len(pwd) % 16)  # Key padding
    pwd += chr(length) * length
    flag = 1
    with open('InstructionTable.txt', 'r') as ins: # Opening Instruction Table as read mode
        for line in ins:
            words = line.split(' ')
            ctr = ctr + 1
            if (int(feature_val[ctr]) < t):          # if feature value is less than 't' choose left share
                encrypted_share = words[0]
                cipher_text0 = base64.b64decode(encrypted_share)
                iv = cipher_text0[:AES.block_size]
                decryption_suite = AES.new(pwd, AES.MODE_CFB, iv)
                plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])
                shares.append(plain_text0)
            else:                                     # if feature value is not less than 't' choose right share
                encrypted_share = words[1]
                cipher_text0 = base64.b64decode(encrypted_share)
                iv = cipher_text0[:AES.block_size]
                decryption_suite = AES.new(pwd, AES.MODE_CFB, iv)
                plain_text0 = decryption_suite.decrypt(cipher_text0[AES.block_size:])
                shares.append(plain_text0)
        try:
            hdpwd = tss.reconstruct_secret(shares)    # try to generate harden password using m shares.
            hdpwd = hdpwd[0:32]
            hdpwd = Decimal(hdpwd)
        except Exception:                             # if m shares are not correct than it will not generate harden password and will through a error, which is covered in exception.
            flag = 0
        if flag == 1:
            return hdpwd                              # if harden password is successfully created by m shares return harden password otherwise 0
        else:
            return 0
    ins.close()                                       # closing instruction table file





# Execution of code starts from here


pass_input = raw_input("Enter path of input file containing password and features value\n")  # Taking path of input file from user
try:
    pass_file = open(pass_input, 'r')                                  # Error handling: If a user give wrong path of file, program stop its execution and get closed
except IOError:
    sys.exit("Input path is wrong. Closing program......")


lines = pass_file.readlines()  # reading input file , which contain multiple login attempt
f = open("output.txt", 'a')  # creating a output fie, 1 for every legimate login otherwise 0
f.truncate()  # deleting all previous enteries from output file

n_users = len(lines) / 2;  # Reading password and feature vector for ith user
for i in range(0, n_users, 1):
    password = lines[2 * i]  # Reading even lines from file for password
    password = password.strip('\n')
    if i==0:
        m=len(password)-1    #calculating number of feature values based on password's length

    feature_val = lines[2 * i + 1] # Reading odd lines from file for password
    feature_val = feature_val.strip('\n')  # recording feture value of ith user in form of array
    feature_val = feature_val.split(',')
    if len(feature_val) != m:
        f.write('0\n')
        print 'Login Attempt '+ str(i+1)  +': Number of Feature values are wrong....moving to next login'    #checking if feature vector is of m size or not, where m is length of password -1 , if not continue to next login and write 0 to output file
        continue
    exit1=1                       #initializing a flag, if feature value type is not convertable to int, it helps code to continue to next login attempt
    for x in range(len(feature_val)):
        try:
            feature_val[x] = int(feature_val[x])                              # checking if feature value is integer or can be defined as integer
        except ValueError:
            f.write('0\n')
            print 'Login Attempt '+ str(i+1) +': Feature value type is wrong for login, moving to next login'
            exit1=0                                                            # set flag =0, if feature value is not integer and write 0 to output file
            break
    if(exit1==0):                                                              # continue to next login attempt if feature value is not integer
        continue
    # call functions to compute
    if i <= 4:
        if i == 0:
            first_hdpwd = initial_hdpwd(password)  # creating initial harden password which is used for initializing instruction table
        f.write('1\n')                      # as first 5 login is always legimate so return 1 to output file
        history(feature_val, first_hdpwd)   # storing first 5 login feature values in history table
        if (i == 4):
            create_inst_table(password, first_hdpwd)  # creating instruction table after 5 legimate logins
    else:
        password = password.strip('\n')
        re_hpwd = reconstruct_shares(feature_val, password) # calling reconstruct_shares function for creating harden password and checking if the login attempt is legimate or not
        if re_hpwd == 0:
            f.write('0\n')                                   # if login attempt not legimate write 0 to output file
        else:
            f.write('1\n')                                  # if legimate login write 1 in output file
            create_inst_table(password, re_hpwd)            # updateng history file and instruction table input
print 'Please check for output.txt for answers.'
f.close()                                                    #closing output file
pass_file.close()                                            #closing input file