from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC

def read_message(file_name):
    with open(file_name, 'r') as file:
        return file.read().encode("utf-8")

def load_recipient_public_key(recipient):
    with open(f"keys/{recipient}Public.pem", 'r') as file:
        return RSA.import_key(file.read())

def encrypt_aes_key(aes_key, recipient_public_key):
    rsa_cipher = PKCS1_OAEP.new(recipient_public_key)
    return rsa_cipher.encrypt(aes_key)

def encrypt_message(message, aes_key):
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
    return ciphertext, tag, aes_cipher.nonce

def generate_mac_key(key_path):
    mac_key = get_random_bytes(16)  # 16 bytes key for HMAC
    with open(key_path, 'wb') as file:
        file.write(mac_key)
    return mac_key

def create_mac(ciphertext, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(ciphertext)
    return h.digest()

def write_encrypted_data(file_name, aes_key_enc, nonce, tag, ciphertext, mac):
    with open(file_name, "wb") as file:
        file.write(aes_key_enc)
        file.write(nonce)
        file.write(tag)
        file.write(ciphertext)
        file.write(mac)

def encrypt(file_name, recipient):
    message = read_message(file_name)
    recipient_public_key = load_recipient_public_key(recipient)

    aes_key = get_random_bytes(16)
    aes_key_enc = encrypt_aes_key(aes_key, recipient_public_key)

    ciphertext, tag, nonce = encrypt_message(message, aes_key)

    mac_key = generate_mac_key("./keys/mac_key.bin")
    mac = create_mac(ciphertext, mac_key)

    write_encrypted_data("encrypted.bin", aes_key_enc, nonce, tag, ciphertext, mac)