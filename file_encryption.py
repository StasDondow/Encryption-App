from aes128 import AES
import random


key_length = 16

def generate_key(fpath, show_message=True):
    """ The function generates a sequence of bytes of length n. """
    random_bytes = [random.randint(0, 255) for i in range(key_length)]
    with open(fpath, "wb") as f:
        f.write(bytes(random_bytes))
    if show_message:
        print("Key successfully generated!")


def read_file(fpath):
    """ Reads the bytes of a file. """
    try:
        with open(fpath, "rb") as f:
            text = f.read()
        return text
    except FileNotFoundError:
        print("No such file!")


def encrypt_file(plaintext_fpath, key_fpath, show_message=True):
    plaintext = read_file(plaintext_fpath)
    key = read_file(key_fpath)
    
    aes = AES()
    ciphertext = aes.encrypt(plaintext, key)
    
    ciphertext_fpath = "".join(plaintext_fpath.split(".")[:-1]) + "_encrypted." + plaintext_fpath.split(".")[-1]
    with open(ciphertext_fpath, "wb") as f:
        f.write(bytes(ciphertext))
        
    if show_message:
        print("File successfully encrypted!")
    

def decrypt_file(ciphertext_fpath, key_fpath, show_message=True):
    ciphertext = read_file(ciphertext_fpath)
    key = read_file(key_fpath)
    
    aes = AES()
    plaintext = aes.decrypt(ciphertext, key)
    
    plaintext_fpath = "".join(ciphertext_fpath.split(".")[:-1]) + "_decrypted." + ciphertext_fpath.split(".")[-1]
    with open(plaintext_fpath, "wb") as f:
        f.write(bytes(plaintext))
        
    if show_message:
        print("File successfully decrypted!")


def start_dialogue():
    print("""
OPTIONS:
    1 - generate key
    2 - enrypt file
    3 - decrypt_file
    4 - exit""")
    while True:
        c = input("\nWhat to do next? ")
        if c == "1":
            fname = input("Enter filename: ")
            generate_key(fname)
        elif c == "2":
            plaintext_fpath = input("Enter plaintext file full path: ")
            key_fpath = input("Enter key file full path: ")
            encrypt_file(plaintext_fpath, key_fpath)
        elif c == "3":
            ciphertext_fpath = input("Enter ciphertext file full path: ")
            key_fpath = input("Enter key file full path: ")
            decrypt_file(ciphertext_fpath, key_fpath)
        elif c == "4":
            print("Goodbye!")
            break
        else:
            print("No such option! Try again!")

