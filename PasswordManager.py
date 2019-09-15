#!/usr/bin/env python3
#
# Password manager: handles hashing and comparing for passwords used in LikedSavedDownloaderServer
# I'm no expert so use and trust at your own risk!
#
from passlib.context import CryptContext
import sys

# Even if this file gets compromised, it'll still be hard to use for anything
passwordsFilename = "passwords.txt"

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

passwords = []
def cachePasswords():
    global passwords
    passwordsFile = open(passwordsFilename, "r")
    passwords = passwordsFile.readlines()
    passwordsFile.close()
    
def verify(password):
    if not len(passwords):
        cachePasswords()
    if not len(passwords):
        raise Exception("Tried to verify a password, but {} has no passwords or does not exist!")
    
    for storedPassword in passwords:
        if password_context.verify(password, storedPassword[:-1]):
            return True
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Wrong number of arguments!\n"
              "PasswordManager: Adds a password to the passwords file.\n"
              "Usage:\n  python PasswordManager.py \"your password\"")
    else:
        passwordHashed = password_context.hash(sys.argv[1])
        
        passwordsOut = open(passwordsFilename, "a")
        passwordsOut.write(passwordHashed + "\n")
        passwordsOut.close()
