Faiz Aladin
November 28th, 2020

Final Project Proposal

Idea: Password Generator and Vault

	The user should be able to create a label for a login that can be stored in the vault. For example, if the user wants to make a login for a new Hulu account, they can label the login Hulu and provide their username and the conditions required to satisfy the password characters and symbol requirement. 
	
	The password will be randomly generated using a mix of capital and lowercase letters. The length of the password as well as the number of symbols in the password are dictated by the user. 

	This idea is similar to 1Password except it will be written in python. 1Password can be used as a reference for a better understanding. 

	All vaults are encrypted upon closing and can be decrypted when accessed. GUI uses Tkinter to give a more modern OS look. Encryption uses RSA and AES keys from PyCrypto. Master Passwords are encrypted as well using an MD5 hash algorithm. 

Test Runs:
Given program to three different age groups: my friends, parents and grandparents
Code worked smoothly in all the last test runs done by each group

What to work on:
Creating an application of project
Integrate with terminal to hide vault files and RSA keys in a root directory
Able to store keychains when user enters information into a web browser

WORKS CITED:
Pycrypto documentation
TKinter, ttk documentation

Before you run the program:
You need to go into terminal and enter "pip3 install cryptodome" into commandline
You will also need to use python3 to run the program (finalproj_faladin.py)

Run finalproj_faladin.py

Enjoy!
