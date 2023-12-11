from generateKey import *
from encrypt import *
from decrypt import *
import sys

def main():
    if len(sys.argv) == 1:
        inp = input(">> ")
        args = inp.split()
        command = args[0]
        args = [args[i] for i in range(1, len(args))]
    else:
        command = sys.argv[1]
        args = [sys.argv[i] for i in range(2, len(sys.argv))]

    match command:
        case "generate":
            if len(args) < 1:
                print("Too Few Arguments Provided")
            else:
                generate(args[0])
        case "encrypt":
            if len(args) < 2:
                print("Too Few Arguments Provided")
            else:
                encrypt(args[0], args[1])
        case "decrypt":
            if len(args) < 2:
                print("Too Few Arguments Provided")
            else:
                decrypt(args[0], args[1])
        case _:
            print("Invalid Command Given")

    # generate("Alice")
    # generate("Bob")
    # encrypt("message.txt", "Bob")
    # decrypt("Transmitted_Data.bin", "Bob")

if __name__ == "__main__":
    main()
