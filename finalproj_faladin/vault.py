#Faiz Aladin
#December 5th
import os.path
from os import path
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import tkinter as tk
from tkinter import ttk
import atexit
import math
import random
from random import shuffle

class Vault:
    #vault constructor
    #takes username and password from user class
    def __init__(self, vaultName, masterpass):
        #creates vault using username input
        self.vaultName = vaultName + "_vault"
        #checks to see if a vault with the username already exists
        if (path.isfile(self.vaultName)):
            return
        #makes a new vault with user password(hashed) and named with the inputed username
        inFile = open(self.vaultName, "wt")
        inFile.write(masterpass + '\n')
        inFile.close()

#public
    #alphabetically organizes logins by label name in vault_frame
    def sorting(self, filename):
        #reads vault and stores by line
        infile = open(filename)
        words = infile.readlines()
        infile.close()
        #stores hashed password(we do not want to include this in the sorting)
        temp = words[0]
        #sorts the vault
        words.sort()
        words.remove(temp)
        outfile = open(self.vaultName, "w")
        #adds the hashed password first then sorted vault
        outfile.writelines(temp)
        for i in words:
            outfile.writelines(i)
        outfile.close()

    #Adds loging with label, username, and password within the vault
    def addLogin(self, website, username, password):
        vault = open(self.vaultName, "a+")
        #adds login info to the vault
        vault.write(f'{website} {username} {password} \n')
        vault.close()
        #sorts it into the vault
        self.sorting(self.vaultName)

    #creates RSA keys for encryption and decryption of file(keeps it protected)
    def encrypt(self):
        #generates random private key
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open(self.vaultName + "private.pem", "wb")
        file_out.write(private_key)
        file_out.close()
        #generates random public key
        public_key = key.publickey().export_key()
        file_out = open(self.vaultName + "receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def encryptFile(self):
        self.encrypt()
        inFile = open(self.vaultName, "rt")
        #reads vault info to be encrypted with public key
        totaltext = inFile.read()
        masterpass = totaltext[0:totaltext.index('\n')]
        #data is encoded in utf-8 to be read
        data = totaltext.encode("utf-8")
        file_out = open(self.vaultName, "wb")
        #opens public key file
        recipient_key = RSA.import_key(open(self.vaultName+"receiver.pem").read())
        #take hashed password of user and turns it into a byte key
        b = bytes(masterpass, "utf-8")
        session_key = b

        #encrypts the hashed password with the public key
        #the hashed password is the AES session key
        #adds another level of protection
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()

    def decryptFile(self, userpass):
        file_in = open(self.vaultName, "rb")
        #reads private key file
        private_key = RSA.import_key(open(self.vaultName + "private.pem").read())
        #takes the encrypted AES session key
        enc_session_key, nonce, tag, ciphertext = \
           [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        # decrypts the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        #if the user's hashed input does not match the hashed password the file will not decrypt
        if userpass.encode('utf-8') != session_key:
            return False

        #decrypts the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        file_in = open(self.vaultName, "wt")
        file_in.write(data.decode("utf-8"))

        return True

    #vault GUI
    def display(self, menuwin):
        #writes over user GUI in the users class
        #makes a new window for the user vault
        win = menuwin
        win.title(self.vaultName)
        win.resizable(width=1, height=1)
        #creates vault frame for treeview
        vault_frame = ttk.Frame(win)
        vault_frame.grid(column=0, row=0, sticky=tk.NSEW)
        #Stops the window from resizing
        win.resizable(width=0, height=0)
        #creates tree view for login infos to apppear and be read in an easy way
        vault_tree = ttk.Treeview(vault_frame, columns=('website', 'username', 'password'))
        #headings for user to understand
        vault_tree.heading('website', text='Website')
        vault_tree.heading('username', text='Username')
        vault_tree.heading('password', text='Password')
        vault_tree['show'] = 'headings'
        #opens vault to be read into the treeview
        vault = open(self.vaultName, "rt")
        first = True
        #writes each login line by line
        for line in vault:
            #ignores the first line the hashed password
            if first:
                first = False
                continue
            #inserts the lines into the treeview
            vault_tree.insert("", index='end', values=line)
        #draws the vault tree into the vault frame
        vault_tree.grid(column=0, row=0, columnspan=2, sticky=tk.NSEW)
        #creates a scrollbar for all logins to be seen
        vault_scrl = ttk.Scrollbar(vault_frame, orient='vertical', command=vault_tree.yview)
        vault_tree.configure(yscrollcommand=vault_scrl.set)
        vault_scrl.grid(column=2, row=0, sticky=tk.NS + tk.W)
        #organizes buttons and treeview in vault frame
        vault_frame.columnconfigure(0, weight=1)
        vault_frame.rowconfigure(0, weight=1)
        #creates an add login button to add logins
        addlogin = ttk.Button(vault_frame, text = "Add Login")
        addlogin.grid(column= 0, row = 1, sticky = tk.N + tk.EW)
        #logs out of the vault and takes user back to user GUI
        logout = ttk.Button(vault_frame, text = "Logout")
        logout.grid(column= 1, row = 1, sticky = tk.N + tk.EW)
        #reorganizes vault frame
        vault_frame.columnconfigure(1, weight=1)
        vault_frame.rowconfigure(1, weight=1)
        #creates add login frame after user presses "add login"
        addlogin_frame = ttk.Frame(win)
        addlogin_frame.grid(column = 0, row = 1, stick = tk.NSEW)
        win.rowconfigure(1, weight = 1)
        addlogin_frame.grid_remove()
        #delete loging button is created
        dellogin = ttk.Button(vault_frame, text = "Delete Login")
        #modify login button is created
        modlogin = ttk.Button(vault_frame, text = "Modify Login")
        #entry boxes for website, username and password are created
        labweb = ttk.Label(addlogin_frame, text = "Website: ")
        labuser = ttk.Label(addlogin_frame, text = "Username: ")
        labpass = ttk.Label(addlogin_frame, text = "Password: ")
        inputweb = ttk.Entry(addlogin_frame)
        inputuser = ttk.Entry(addlogin_frame)
        inputpass = ttk.Entry(addlogin_frame)
        #entry boxes and labels are drawn
        labweb.grid(column = 0, row = 1, sticky = tk.EW)
        labuser.grid(column = 0, row = 2, sticky = tk.EW)
        labpass.grid(column = 0, row = 3, sticky = tk.EW)
        inputweb.grid(column = 1, row = 1, columnspan = 2)
        inputuser.grid(column= 1, row = 2, columnspan = 2)
        inputpass.grid(column = 1, row = 3, columnspan = 2)
        #creates a separator between entry boxes and sliders for generate password
        separator = ttk.Separator(addlogin_frame, orient='vertical')
        separator.grid(column = 4, row = 1, rowspan = 4, sticky = tk.NS, padx=15)

        #creates control variables for slider to get updated values of sliders
        lengthvalue = tk.StringVar()
        lengthvalue.set('4')
        numbervalue = tk.StringVar()
        numbervalue.set('0')
        charvalue = tk.StringVar()
        charvalue.set('0')

        #sliders for length of password, number of numbers and characters in the passsword
        #lambda function is used to display and integer next to each slider
        #minimum length of a slider is 4. If the number slider or character slider value exceeds the length slider value,
        #only 4 characters will be generated
        lengthslider = ttk.Scale(addlogin_frame, from_=4, to=20, variable = lengthvalue, command=lambda s:lengthvalue.set('%d' % float(s)))
        lengthslider.grid(column = 6, row = 1, padx = 10)
        lengthdisplay = ttk.Label(addlogin_frame, textvariable = lengthvalue)
        lengthdisplay.grid(column=7, row = 1)
        lengthlabel = ttk.Label(addlogin_frame, text = "Length", padding = "16 0 16 0", borderwidth=1, relief='solid')
        lengthlabel.grid(column = 5, row = 1)
        numberslider = ttk.Scale(addlogin_frame, from_=0, to=10, variable = numbervalue, command=lambda s:numbervalue.set('%d' % float(s)))
        numberslider.grid(column = 6, row = 2, padx = 10)
        numdisplay = ttk.Label(addlogin_frame, textvariable = numbervalue)
        numdisplay.grid(column=7, row = 2)
        numberlabel = ttk.Label(addlogin_frame, text = "Digits", padding = "12 0 12 0", borderwidth=1, relief='solid')
        numberlabel.grid(column = 5, row = 2)
        characterslider = ttk.Scale(addlogin_frame, from_=0, to=10, variable = charvalue, command=lambda s:charvalue.set('%d' % float(s)))
        characterslider.grid(column = 6, row = 3, padx = 10)
        chardisplay = ttk.Label(addlogin_frame, textvariable = charvalue)
        chardisplay.grid(column=7, row = 3)
        characterlabel = ttk.Label(addlogin_frame, text = "Symbols", padding = "10 0 10 0", borderwidth=1, relief='solid')
        characterlabel.grid(column = 5, row = 3)

        #submit and cancel buttons to enter or stop making a new login
        submit = ttk.Button(addlogin_frame, text = "Submit")
        cancel = ttk.Button(addlogin_frame, text = "Cancel")
        genpass = ttk.Button(addlogin_frame, text = "Gen Pass")
        submit.grid(column = 1, row = 4)
        genpass.grid(column = 6, row = 4)
        cancel.grid(column = 2, row = 4, sticky = tk.S)

        #adds login info to vault
        def pressAddLogin():
            addlogin_frame.grid()
            #draws modify and delete buttons
            dellogin.grid(column = 0, row = 2, sticky = tk.N + tk.EW)
            modlogin.grid(column = 1, row = 2, stick = tk.N + tk.EW)
            win.update()

        def pressCancel():
            #removes values from entry boxes for website, username and password
            inputweb.delete(0, 'end')
            inputuser.delete(0, 'end')
            inputpass.delete(0, 'end')
            #removes add login frame, delete button, and modify button
            addlogin_frame.grid_remove()
            dellogin.grid_remove()
            modlogin.grid_remove()

        #adds login to the vault tree and vault
        def pressSubmit():
            #gets values from entry boxes
            website = inputweb.get().capitalize()
            user = inputuser.get()
            password = inputpass.get()
            #checks to see if any of the entry boxes are empty
            if (website == "" or user == "" or password == ""):
                return
            #adds login info to vault
            self.addLogin(website, user, password)
            #deletes entries in the treeview
            x = vault_tree.get_children()
            for item in x:
                vault_tree.delete(item)
            vault = open(self.vaultName, "rt")
            #re adds logins from the newly sorted vault
            first = True
            for line in vault:
                if first:
                    first = False
                    continue
                vault_tree.insert("", index='end', values=line)
            vault_tree.grid(column=0, row=0, columnspan=2, sticky=tk.NSEW)
            #clears entry boxes
            inputweb.delete(0, 'end')
            inputuser.delete(0, 'end')
            inputpass.delete(0, 'end')

        def passing():
            pass
        #logs out of the user's vault
        def pressLogout():
            vault_frame.grid_forget()
            addlogin_frame.grid_forget()
            #encrypts file when vault is closed
            self.encryptFile()
            #prevents double encrytion if user force quits
            atexit.unregister(quit)
            #prevents double encryption after user closes main window
            win.protocol("WM_DELETE_WINDOW", win.destroy)

        #generates random password
        def pressgenpass():
            inputpass.delete(0, 'end')
            #deletes any entry in the password entry box
            #values of all letters, numbers and symbols
            alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
                        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
            numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',]
            symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']
            #gets values from sliders and stores them
            inputlength = int(lengthvalue.get())
            inputnumbers = int(numbervalue.get())
            inputsymbols = int(charvalue.get())
            #checks to see how many letters need to be added to the password
            inputletters = inputlength - inputnumbers - inputsymbols
            password = []

            #appends # of random numbers and characters to password list specified by user
            for i in range(inputnumbers):
                password.append(numbers[random.randrange(9)])
            for y in range(inputsymbols):
                password.append(symbols[random.randrange(9)])
            #checks to see if value is negative or letters need to be added
            if inputletters > 0:
                for z in range(inputletters):
                    password.append(alphabet[random.randrange(25)])
            #randomly shuffles contents of list
            inpass = ("".join(random.sample(password, inputlength)))
            #adds password to entry box
            inputpass.insert(0, inpass)
            #resets sliders
            lengthslider.set(0)
            numberslider.set(0)
            characterslider.set(0)

        #deletes login from treeview and vault
        def pressdelete():
            #takes login selected by user
            temp = vault_tree.focus()
            temp = vault_tree.index(temp)
            openFile = open(self.vaultName, "r")
            lines = openFile.readlines()
            openFile.close()
            #deletes specified login from vault
            del lines[temp + 1]
            openFile = open(self.vaultName, "w+")
            for i in lines:
                openFile.writelines(i)
            openFile.close()
            #deletes treeview entries
            x = vault_tree.get_children()
            for item in x:
                vault_tree.delete(item)
            vault = open(self.vaultName, "rt")
            first = True
            #adds logins from modified vault
            for line in vault:
                if first:
                    first = False
                    continue
                vault_tree.insert("", index='end', values=line)
            vault_tree.grid(column=0, row=0, columnspan=2, sticky=tk.NSEW)

        #modifies a login
        def pressmodify():
            #clears entry boxes
            inputweb.delete(0, 'end')
            inputuser.delete(0, 'end')
            inputpass.delete(0, 'end')
            #takes values from selected login
            temp = vault_tree.focus()
            val = vault_tree.item(temp)
            #stores dictionary values in a list
            access = val['values']
            #deletes login from vault and tree view
            pressdelete()
            #put the values in the entry boxes to be modified
            inputweb.insert(0, access[0])
            inputuser.insert(0, access[1])
            inputpass.insert(0, access[2])

        #buttons are configured to utilize functions above
        addlogin.configure(command = pressAddLogin)
        cancel.configure(command = pressCancel)
        submit.configure(command = pressSubmit)
        logout.configure(command = pressLogout)
        genpass.configure(command = pressgenpass)
        dellogin.configure(command = pressdelete)
        modlogin.configure(command = pressmodify)

        #adds padding to buttons and lables in window
        for child in win.winfo_children():
            child.configure(padding = 15)

        #encrypts file and closes window
        def quit():
            self.encryptFile()
            win.destroy()

        #used if the user force quits the program (still has to encrypt the file)
        atexit.register(quit)
        #encrypts the file if the user hits the X button or uses shortcut
        win.protocol("WM_DELETE_WINDOW", pressLogout)

        #mainloop
        win.mainloop()
