#!/usr/bin/env python
#
# Password manager: handles hashing and comparing for passwords used.
# I'm no expert so use and trust at your own risk!
#
from passlib.context import CryptContext

# It's not strictly necessary to import these, but I do it here for PyInstaller
# (see https://github.com/pyinstaller/pyinstaller/issues/649)
import argon2
import cffi
import configparser
import passlib.handlers
import passlib.handlers.argon2
import passlib.handlers.sha2_crypt
import passlib.handlers.bcrypt

import sys
import os
import json
import getpass

# Even if this file gets compromised, it'll still be hard to use for anything due to salting
accountsFilename = "accounts.json"

password_context = CryptContext(
    # Replace this list with the hash(es) you wish to support.
    # this example sets pbkdf2_sha256 as the default,
    # with additional support for reading legacy des_crypt hashes.
    schemes=["argon2", "sha512_crypt", "bcrypt"],

    # Automatically mark all but first hasher in list as deprecated.
    # (this will be the default in Passlib 2.0)
    deprecated="auto",

    # Optionally, set the number of rounds that should be used.
    # Appropriate values may vary for different schemes,
    # and the amount of time you wish it to take.
    # Leaving this alone is usually safe, and will use passlib's defaults.
    ## pbkdf2_sha256__rounds = 29000,
    )

accounts = {}

# Note that this class needs to be kept simple, otherwise JSON serialization will break
class Account:
    def __init__(self, username, passwordHashed):
        self.username = username
        self.passwordHashed = passwordHashed

def havePasswordsBeenSet():
    return os.path.exists(accountsFilename)

def loadAccounts():
    global accounts

    if not havePasswordsBeenSet():
        return

    passwordsFile = open(accountsFilename, "r")
    accountsJson = passwordsFile.readlines()
    passwordsFile.close()

    for line in accountsJson:
        accountParsed = json.loads(line)
        account = Account(accountParsed["username"], accountParsed["passwordHashed"])
        accounts[account.username] = account

def verify(username, password):
    if not accounts:
        loadAccounts()
    if not accounts:
        raise Exception("Tried to verify an account, but {} has no accounts or does not exist!"
                        .format(accountsFilename))
    
    if username not in accounts:
        # Username not found
        return False
    else:
        if password_context.verify(password, accounts[username].passwordHashed):
            return True
    return False

def createAccount(username, password):
    if not accounts:
        loadAccounts()
    if username in accounts:
        return (False, "Failed to create account: Username not unique")

    passwordHashed = password_context.hash(password)
        
    accountPair = Account(username, passwordHashed)
    accountsOutFile = open(accountsFilename, "a")
    json.dump(accountPair.__dict__, accountsOutFile)
    accountsOutFile.write("\n")
    accountsOutFile.close()
    loadAccounts()
    return (True, "Account created successfully")

if __name__ == "__main__":
    print("PasswordManager: Create a new account\n")

    username = input("\tEnter username: ")
    password = None
    while True:
        password = getpass.getpass("\tEnter password: ")
        verifyPassword = getpass.getpass("\tVerify password: ")
        if not password:
            print("Please enter a password")
        elif password != verifyPassword:
            print("Passwords do not match! Try again")
        else:
            break

    result = createAccount(username, password)
    print("[Create Account] {}".format(result[1]))

    if result[0]:
        # To verify
        print("Account created! Please test.")
        username = input("\tEnter username: ")
        password = getpass.getpass("\tEnter password: ")

        print("Authentication successful: {}".format(verify(username, password)))
