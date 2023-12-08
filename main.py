from generateKey import generate
from encrypt import encrypt
from decrypt import decrypt  

def main():
    generate("Alice")
    generate("Bob")
    encrypt("message.txt", "Bob")

    # Simulate transmission by copying the encrypted data to the receiver's folder
    import shutil
    shutil.copy("encrypted.bin", "keys/Bob/")

    # Decrypt the transmitted data at the receiver's end
    decrypt("keys/Bob/encrypted.bin", "Bob")

if __name__ == "__main__":
    main()
