from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def encrypt(fileName, recepient):

    # Read in plaintext message
    inFile = open(fileName, 'r')
    message = inFile.read()
    message = message.encode("utf-8")

    # Grab recpeients public key from keys directory
    recipientPK = RSA.import_key(open(f"keys/{recepient}Public.pem").read())

    aesKey = get_random_bytes(16) # Generate Random AES key
    rsaCipher = PKCS1_OAEP.new(recipientPK) # created a padded RSA cipher
    aesKeyEnc = rsaCipher.encrypt(aesKey) # encrypt AES key with RSA cipher
    aesCipher = AES.new(aesKey, AES.MODE_EAX) # create AES cipher with key
    ciphertext, tag = aesCipher.encrypt_and_digest(message) # encrypt plaintext with AES

    # Output encrpyted AES key, nonce, tag, and encrypted message to file
    outFile = open("encrypted.bin", "wb")
    outFile.write(aesKeyEnc)
    outFile.write(aesCipher.nonce)
    outFile.write(tag)
    outFile.write(ciphertext)
    outFile.close()