import os, json, getpass, string, random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import pyperclip

# Filename of password vault
PASSWORD_FILE = 'passwords.json'


# Function to encrypt data using a password and a salt
def encrypt_data(data, password, salt):
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)  # Derive the key using scrypt key derivation function
    cipher = AES.new(key, AES.MODE_CBC)  # Create an AES cipher with Cipher Block Chaining (CBC) mode
    ciphertext = cipher.encrypt(pad(data, AES.block_size))  # Pad the plain text, then encrypt it
    return cipher.iv + ciphertext # Concatenates the initialization vector (IV) and ciphertext

# Function to decrypt data using a password and a salt
def decrypt_data(data, password, salt):
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)  # Derive the key using scrypt key derivation function
    iv = data[:16]  # Extract the IV (the first 16 bytes of the encrypted data)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create an AES cipher with CBC mode and the given IV
    decrypted_data = unpad(cipher.decrypt(data[16:]), AES.block_size)  # Decrypt the data and unpad it
    return decrypted_data

# Function to save passwords to a file
def save_passwords(passwords, master_password, file=PASSWORD_FILE):
    with open(file, 'wb') as f: # Open the file in binary write mode
        salt = get_random_bytes(16)  # Generate a random salt with 16 bytes
        f.write(salt) # Write the salt to the file
        encrypted_data = encrypt_data(json.dumps(passwords).encode(), master_password, salt)
        f.write(encrypted_data)  # Write the encrypted data to the file

# Function to load passwords from a file
def load_passwords(master_password, file=PASSWORD_FILE):
    try:
        with open(file, 'rb') as f: # Open the file in binary read mode
            salt = f.read(16)  # Read the first 16 bytes for the salt
            encrypted_data = f.read()  # Read the remaining encrypted data
            decrypted_data = decrypt_data(encrypted_data, master_password, salt)
            return json.loads(decrypted_data.decode())
    except FileNotFoundError:
        return {}

# Function to append a password to the passwords dictionary
def add_password(passwords, account, username, password):
    entry = {"username": username, "password": password}
    passwords[account] = entry

# Function to generate a random password on set length
def generate_random_password(length=12):

    # string.ascii_letters = abcdefghijklmnopqrstuvwxyz - upper & lower case.
    # string.digits        = 0123456789
    # string.punctuation   = !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~.
    chars = string.ascii_letters + string.digits + string.punctuation

    return ''.join(random.choice(chars) for _ in range(length)) # Returns a string consisting of length amount of random chars from the chars string


def main():
    print("Welcome to the Post-Quantum Password Manager")
    connected = False  # This is probably bad practice, but it works and should be safe
    
    # Loop until correct masterpassword is provided
    while connected == False: 
        try:
            master_password = getpass.getpass("Enter your master password: ") # Using getpass to safely get masterpassword input from terminal
            passwords = load_passwords(master_password) # Tries to load and decrypt passwords with given masterpassword, error if incorrect
            connected = True # Switches into logged in loop if master password was correct.
        except ValueError:
            print('I hope you didn\'t loose your master password...') # Ouch
            connected = False
    

    # Loop until user decides to quit
    while connected == True:
        # Display menu options
        print("1. Add password \n2. List passwords \n3. Generate random password and copy to clipboard \n4. Quit \n")
        
        try:
            choice = int(input("Choose an option: "))
        except ValueError:
            print('Valid numbers only please')
            continue

        # Handler for user choices
        if choice == 1:  # Add password
            account = input("Enter account name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            add_password(passwords, account, username, password) # Adds password to password dict in memory
            save_passwords(passwords, master_password) # Saves all passwords from password dict to .json file, with new salt & encrypted with master password. 
            print(f"Password for {account} saved.")

        elif choice == 2:  # List passwords
            print("These are your accounts: ")
            for account, entry in passwords.items(): # Listing all accounts in passwords dictionary
                print(account)
            print('\n')
            selected_account = str(input("Choose an account (Will display password):"))
            selected_account_found = False # Boolean flag that becomes true when account is found           
            for account, entry in passwords.items(): # Loops through all passwords
                if(selected_account == account): # User input matches item in password dict 
                    print(f"Account: {account} - Username: {entry['username']} / Password: {entry['password']}")
                    selected_account_found = True
                
            if(selected_account_found == False):
                print('Account not found')
            
            print('\n')

        elif choice == 3:  # Generate random password and copy to clipboard
            length = int(input("Enter the desired length of the random password (default 16): ") or 16)
            random_password = generate_random_password(length)
            pyperclip.copy(random_password)
            print(f"Generated random password of length {length} and copied to clipboard. \n")

        elif choice == 4:  # Quit the application
            break
        else:
            print("Invalid option, please try again")

# Run the main function
if __name__ == "__main__":
    main()