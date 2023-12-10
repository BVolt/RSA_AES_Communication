from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import base64

def load_private_key(private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key

def load_mac_key(recipient):
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

def verify_mac(transmitted_data, mac_key):
    message, received_mac = transmitted_data[:-32], transmitted_data[-32:]
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(message)
    calculated_mac = h.digest()
    return base64.b64encode(calculated_mac).decode() == received_mac.decode()

def decrypt(transmitted_data_path, private_key_path):
    private_key = load_private_key(private_key_path)

    with open(transmitted_data_path, 'rb') as f:
        transmitted_data = f.read()

    encrypted_aes_key, encrypted_nonce, tag, ciphertext = (
        transmitted_data[:private_key.size_in_bytes()],
        transmitted_data[private_key.size_in_bytes():private_key.size_in_bytes() + 16],
        transmitted_data[-32 - 16:-32],
        transmitted_data[-32:]
    )

    mac_key = load_mac_key(recipient)

    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

    # Verify MAC before decryption
    if verify_mac(transmitted_data, mac_key):
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=encrypted_nonce)
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print("Decrypted Message:", decrypted_message.decode())
    else:
        print("MAC verification failed. The message may have been tampered with.")

if __name__ == "__main__":
    transmitted_data_path = "Transmitted_Data"
    private_key_path = "BobPrivate.pem"  # Adjust based on your key file
    decrypt(transmitted_data_path, private_key_path)
