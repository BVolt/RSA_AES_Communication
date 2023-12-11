from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC

# Open and read the contents of the specified file, then encode it to UTF-8 bytes.
def read_message(file_name):
    with open(file_name, 'r') as file:
        return file.read().encode("utf-8")

# Open and read the recipient's public key from a PEM file.
def load_recipient_public_key(recipient):
    with open(f"keys/{recipient}Public.pem", 'r') as file:
        return RSA.import_key(file.read())

# Encrypt the AES key using the recipient's RSA public key.
def encrypt_aes_key(aes_key, recipient_public_key):
    rsa_cipher = PKCS1_OAEP.new(recipient_public_key)
    return rsa_cipher.encrypt(aes_key)

# Encrypt the message using AES encryption.
def encrypt_message(message, aes_key):
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
    return ciphertext, tag, aes_cipher.nonce

# Generate a random 16-byte key for HMAC and write it to a file.
def generate_mac_key(key_path):
    mac_key = get_random_bytes(16)  # 16 bytes key for HMAC
    with open(key_path, 'wb') as file:
        file.write(mac_key)
    return mac_key

# Create an HMAC of the ciphertext using SHA256 as the hash function.
def create_mac(ciphertext, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(ciphertext)
    return h.digest()

# Write the encrypted AES key, nonce, tag, ciphertext, and MAC to a file.
def write_encrypted_data(file_name, aes_key_enc, nonce, tag, ciphertext, mac):
    with open(file_name, "wb") as file:
        file.write(aes_key_enc)
        file.write(nonce)
        file.write(tag)
        file.write(ciphertext)
        file.write(mac)

def encrypt(file_name, recipient):
    # Grab message and recpient public key
    message = read_message(file_name)
    recipient_public_key = load_recipient_public_key(recipient)

    # Generate a random AES key and encrypt it with the recipient's public key.
    aes_key = get_random_bytes(16)
    aes_key_enc = encrypt_aes_key(aes_key, recipient_public_key)

    # Encrypt the message with the AES key.
    ciphertext, tag, nonce = encrypt_message(message, aes_key)

    # Generate a MAC key and create a MAC for the ciphertext.
    mac_key = generate_mac_key("./keys/mac_key.bin")
    mac = create_mac(ciphertext, mac_key)

    # Write all necessary components for decryption into a file.
    write_encrypted_data("Transmitted_Data.bin", aes_key_enc, nonce, tag, ciphertext, mac)