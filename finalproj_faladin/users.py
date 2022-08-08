#Faiz Aladin
#December 2nd  2020
from vault import *
from Crypto.Hash import MD5
import os.path
from os import path
import tkinter as tk
from tkinter import ttk
import atexit


class Users:
    #creates a dictionary with usernames as keys and vaults as values
    def __init__(self):
        self.Accounts = {}
        for file in os.listdir():
            if file.endswith("_vault"):
                #looks for vaults created in the folder
                username = file[0:file.index('_')]
                self.Accounts.update({username : Vault(username, "")})
                #adds them to the accounts dictionary


    def createAccount(self, username, password):
        password = self.hasher(password)
        #encrypts user's password
        if self.Accounts.get(username):
            return 1
        #if the username already exists return 1 to display error message
        self.Accounts.update({username : Vault(username, password)})
        #if the username does not exist add the username and vault to accounts
        return Vault(username, password)
        #returns the vault after adding it to the dictionary

    #encrypts the user's password using the MD5 hash algorithmn
    def hasher(self, password):
        hasher = MD5.new()
        hasher.update(password.encode('utf-8'))
        #encodes the password so it can be read from the text file
        return hasher.hexdigest()

    #takes user's entries and uses them to access their vault
    def accessAccount(self, username, password):
        password = self.hasher(password)
        #hashes user's password input
        vault = self.Accounts.get(username, False)
        if vault:
            temp = vault.decryptFile(password)
            #if the file successfully decrypts,the vault will open
            if temp:
                return vault
            else:
            #otherwise an error message will display
                return 1
        else:
            return 1

#Graphics for USER  GUI
    def display(self):
        #Creates Window
        win = tk.Tk()
        win.title('Password Manager')
        win.geometry("600x410")
        win.configure(background = '#ececec')
        win.resizable(height = 0, width = 0)
        #Creates the menu frame for the sign up and login button
        menu_frame = ttk.Frame(win)
        menu_frame.grid(column=0, row=0, sticky = tk.NSEW)
        #intro message
        intro = ttk.Label(menu_frame, text = "Welcome to Password Manager. \n Login or Sign Up below:",
                          justify = 'center', padding = 40)
        intro.grid(column=0, row=0)
        #login button
        login = ttk.Button(menu_frame, text = "Login", width = 20)
        login.grid(column=0, row=1)
        space = ttk.Label(menu_frame)
        space.grid(column = 0, row = 2)
        #signup button
        signup = ttk.Button(menu_frame, text = "Sign Up", width = 20)
        signup.grid(column=0, row=3)

        #Frame appears when the user presses login
        login_frame = ttk.Frame(win)
        login_frame.grid(column = 0, row = 1)
        login_frame.grid_remove()
        #Entry box and label for username
        inputuser = ttk.Entry(login_frame)
        inputuserlabel = ttk.Label(login_frame, text = "Username:")
        #Entry  box and label for password
        inputpass = ttk.Entry(login_frame, show="*")
        inputpasslabel = ttk.Label(login_frame, text = "Password:")
        inputuserlabel.grid(column =  0, row = 0)
        #Drawing username and password labels and entry boxes
        inputuser.grid(column =  1, row =  0, columnspan = 2)
        inputpass.grid(column =  1, row =  1, columnspan = 2)
        inputpasslabel.grid(column =  0, row = 1)
        #Error message used if user submits wrong credentials
        errorlabel = ttk.Label(login_frame, justify='center')
        errorlabel.grid(column = 1, row = 2, columnspan = 2)
        #Makes error label red
        style = ttk.Style()
        style.configure("Red.TLabel", foreground = "red")
        errorlabel.configure(style = "Red.TLabel")
        #creates submit and cancel buttons for login and signup
        submit = ttk.Button(login_frame, text = "Submit")
        cancel = ttk.Button(login_frame, text = "Cancel")
        submit.grid(column = 1, row = 3)
        cancel.grid(column = 2, row = 3)

        #user presses login to enter their credentials
        def presslogin():
            #draws login frame
            login_frame.grid()
            #removes the signup button and configures the submit button to access an account
            signup.grid_remove()
            submit.configure(command = lambda : presssubmit(1))
            win.update()

        #user presses signup to create an account
        def presssignup():
            #draws login frame
            login_frame.grid()
            #removes login button and configures the submit button to create an account
            login.grid_remove()
            submit.configure(command = lambda : presssubmit(2))
            win.update()

        #user presses cancel to go back to main page
        def presscancel():
            #deletes what is in the entry boxes for username and password
            inputuser.delete(0, 'end')
            inputpass.delete(0, 'end')
            #removes error message and login frame
            errorlabel.grid_remove()
            login_frame.grid_remove()
            #redraws login and signup buttons
            login.grid()
            signup.grid()

        #user presses submit to either create or access an account
        def presssubmit(option):
            #removes error messages
            errorlabel.grid_remove()
            #takes in user input from entry boxes
            username = inputuser.get()
            password = inputpass.get()
            #removes user input from entry boxes
            inputuser.delete(0, 'end')
            inputpass.delete(0, 'end')

            #The submit button can be configured to either create or access an account
            if option == 1:
                errorlabel.configure(text = "Incorrect Username or Password\nTry Again.")
                var = self.accessAccount(username, password)
            elif option == 2:
                errorlabel.configure(text="Username is already taken")
                var = self.createAccount(username, password)
            #if the user input does not match credentials, error message is displayed
            if var == 1:
                errorlabel.grid()
            #if credentials are correct, vault is displayed
            else:
                login_frame.grid_remove()
                signup.grid()
                login.grid()
                win.update()
                var.display(win)

        #binds button to functions written above
        signup.configure(command = presssignup)
        login.configure(command = presslogin)
        cancel.configure(command = presscancel)

        #configures frames to make buttons and lables align to the window
        menu_frame.columnconfigure(0, weight = 1)
        win.columnconfigure(0, weight = 1)
        win.rowconfigure(0, weight = 1)
        win.rowconfigure(1, weight = 1)

        #main loop
        win.mainloop()
