from generateKey import *
from encrypt import *
from decrypt import *

def main():
    generate("Alice")
    generate("Bob")
    encrypt("message.txt", "Bob")
    decrypt("encrypted.bin", "Bob")

if __name__ == "__main__":
    main()
