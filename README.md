# 2FA
Zero Effort Key Board Based 2 Factor Authentication:
The goal of	this project is	to implement a zero-effort two-factor authentication scheme. To	simplify the project, we assume	that a user	types a	password at	a client machine. A	trusted	component at the client	records	the	typed password and captures	keystroke feature values. The client securely sends	the	password and keystroke feature values to a server where	the	actual authentication is done. Thus, the	server implements the functionality	outlined below for a given user	U.


Dependencies-
#
#Code is written in Python 2.7. Do not attempt to use Python 3.x to execute. It may not work
#
#The following libraries are needed to be installed for execution-
#decimal
#tss
#random
#io
#base64
#rstr
#numpy
#sys
#Crypto.Cipher
#Random
************************************************************************************************************************
#Build Instructions-
1. Install all dependences
2. Execute CreateShares.py for initialization
3. Execute DecryptedInstructions.py to check whether the shares can be decrypted and reconstructed
4. Execute DecryptHistoryFileContents.py to check whether the history file has been initialized correctly.
5. Execute Login.py and provide the path of the input file
6. Check output.txt file in the executing folder to check whether access has been granted or denied. 
7. Grant is represented by 1 on the output.txt file. Deny is represented by 0 on the output.txt file. 
