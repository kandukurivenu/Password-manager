import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from getpass import getpass
import json
import random
import string
import re

PASSWORD_FILE = 'passwords.json'

def generate_salt(size=16):
    return os.urandom(size)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_password(password: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_password).decode('utf-8')

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    encrypted_password = base64.b64decode(encrypted_password.encode('utf-8'))
    iv = encrypted_password[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_password = decryptor.update(encrypted_password[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_password = unpadder.update(decrypted_padded_password) + unpadder.finalize()
    return decrypted_password.decode('utf-8')

def load_passwords(master_password: str):
    if not os.path.exists(PASSWORD_FILE):
        return {}

    with open(PASSWORD_FILE, 'r') as file:
        data = json.load(file)

    salt = base64.b64decode(data['salt'].encode('utf-8'))
    key = derive_key(master_password, salt)
    try:
        passwords = {service: decrypt_password(encrypted_password, key) for service, encrypted_password in data['passwords'].items()}
    except:
        print("Incorrect master password or corrupted data.")
        return None
    return passwords

def save_passwords(master_password: str, passwords: dict):
    salt = generate_salt()
    key = derive_key(master_password, salt)
    encrypted_passwords = {service: encrypt_password(password, key) for service, password in passwords.items()}
    data = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'passwords': encrypted_passwords
    }
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(data, file)

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def password_strength(password: str) -> str:
    if len(password) < 8:
        return "Weak"
    elif re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*()_+{}|:\"<>?~`]", password):
        return "Strong"
    else:
        return "Moderate"

def main():
    master_password = getpass('Enter master password: ')
    passwords = load_passwords(master_password)

    if passwords is None:
        return

    while True:
        print("\nOptions:")
        print("1. View passwords")
        print("2. Add new password")
        print("3. Generate new password")
        print("4. Update password")
        print("5. Delete password")
        print("6. Change master password")
        print("7. Search password")
        print("8. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            for service, password in passwords.items():
                print(f"Service: {service}, Password: {password}")

        elif choice == '2':
            service = input("Enter service name: ")
            password = getpass("Enter password: ")
            print(f"Password Strength: {password_strength(password)}")
            passwords[service] = password
            save_passwords(master_password, passwords)

        elif choice == '3':
            length = int(input("Enter password length: "))
            new_password = generate_password(length)
            print("Generated password:", new_password)
            print(f"Password Strength: {password_strength(new_password)}")

        elif choice == '4':
            service = input("Enter service name: ")
            if service in passwords:
                new_password = getpass("Enter new password: ")
                print(f"Password Strength: {password_strength(new_password)}")
                passwords[service] = new_password
                save_passwords(master_password, passwords)
            else:
                print("Service not found.")

        elif choice == '5':
            service = input("Enter service name: ")
            if service in passwords:
                del passwords[service]
                save_passwords(master_password, passwords)
                print(f"Password for {service} deleted.")
            else:
                print("Service not found.")

        elif choice == '6':
            new_master_password = getpass("Enter new master password: ")
            confirm_master_password = getpass("Confirm new master password: ")
            if new_master_password == confirm_master_password:
                save_passwords(new_master_password, passwords)
                master_password = new_master_password
                print("Master password changed successfully.")
            else:
                print("Master passwords do not match.")

        elif choice == '7':
            service = input("Enter service name: ")
            if service in passwords:
                print(f"Service: {service}, Password: {passwords[service]}")
            else:
                print("Service not found.")

        elif choice == '8':
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == '__main__':
    main()
