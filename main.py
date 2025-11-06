from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_strength, hash_pw, verify_password
from getpass import getpass

def menu():
    print("\n Select operation: ")
    print("1: Hash file ")
    print("2: Check file integrity ")
    print("3: AES Encrypt/Decrypt ")
    print("4: RSA Encrypt/Decrypt ")
    print("5: Password Manager ")
    print("0: Exit")


print(
"""
Cryptography toolkit v1.0

\n Welcome, to my toolkit:
    - analyse en hash file for checking the integrity
    - encrypt and decrypt messages with AES and RSA
    - securing password with salting and checking for strength

    All systems are online. dataprotection protocols is used 

    choose an number (0-5)
""")

while True:
    menu()
    choice = input("Enter choice(0-5): ")
    if choice == "0":
        break

    elif choice == "1":
        file_path = input("Enter file path: ")
        print("\n SHA Hash of file is: ", hash_file(file_path))
    
    elif choice == "2":
        file_path1 = input("Enter file path 1: ")
        file_path2 = input("Enter file path 2: ")
        print(verify_integrity(file_path1, file_path2))

    elif choice == "3":
        message = input("Enter message: ")
        key, ciphertext, plaintext = aes_ed(message)
        print("AES key: ", key)
        print("AES Ciphertext: ", ciphertext)
        print("AES Plaintext: ", plaintext)
    
    elif choice == "4":
        message = input("Enter message: ")
        ciphertext, plaintext = rsa_ed(message)
        print("RSA message, encrypted with a public key: ", ciphertext)
        print("RSA message, encrypted with a private key: ", plaintext)

    elif choice == "5":
        while True:
            password1 = getpass("Enter a password to check strength: ")
            print(check_strength(password1))
            if check_strength(password1).startswith("Weak"):
                print("Please choose a stronger password")
            else:
                break        
        hashed_password = hash_pw(password1)
        print("Hashed password: ", hashed_password)
        attempt = getpass("Re-enter the password to verify: ")
        print(verify_password(attempt, hashed_password))

    else:
        print("Invalid choice.")

print("Agent, you are exiting cryptographic, use this tool for sharp and secure")



