from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes

def load_private_key(private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key

def load_mac_key():
    with open("./keys/mac_key.bin", 'rb') as f:
        return f.read()

def decrypt_aes_key(encrypted_aes_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def decrypt_message(encrypted_message, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    decrypted_message = cipher_aes.decrypt(encrypted_message)
    return decrypted_message

def verify_mac(ciphertext, received_mac, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(ciphertext)
    calculated_mac = h.digest()
    return calculated_mac == received_mac

def decrypt(transmitted_data_path, recepient):
    private_key = load_private_key(f"keys/{recepient}Private.pem")

    with open(transmitted_data_path, 'rb') as f:
        transmitted_data = f.read()

    encrypted_aes_key, encrypted_nonce, tag, ciphertext, mac = (
        transmitted_data[:private_key.size_in_bytes()],
        transmitted_data[private_key.size_in_bytes():private_key.size_in_bytes() + 16],
        transmitted_data[-56:-40],
        transmitted_data[private_key.size_in_bytes() + 32:-32], 
        transmitted_data[-32:]
    )

    mac_key = load_mac_key()

    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

    # Verify MAC before decryption
    if verify_mac(ciphertext, mac, mac_key):
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=encrypted_nonce)
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print("Decrypted Message:", decrypted_message.decode())
    else:
        print("MAC verification failed. The message may have been tampered with.")
