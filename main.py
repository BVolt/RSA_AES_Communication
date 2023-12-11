from generateKey import *
from encrypt import *
from decrypt import *
import sys, os

def get_command():
    if len(sys.argv) == 1: # If no commands were given prompt for one
        inp = input(">> ")
        args = inp.split()
        command = args[0]
        args = [args[i] for i in range(1, len(args))]
    else: # Assign command and arguments when given
        command = sys.argv[1]
        args = [sys.argv[i] for i in range(2, len(sys.argv))]

    return command, args

def gen_demo_keys():
    # Create keys for Alice and Bob if they do not exist
    if not os.path.exists('keys/AlicePrivate.pem') or not os.path.exists('keys/AlicePublic.pem'):
        generate("Alice")
    if not os.path.exists('keys/BobPrivate.pem') or not os.path.exists('keys/BobPublic.pem'):
        generate("Bob")

def execute_command(command, args):
    match command: # Switch based on command
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


def main():
    command, args = get_command() # Get Command Line arguments or prompt if none are provided
    gen_demo_keys() # Generate Alice and Bob RSA keys if they do not exist
    execute_command(command, args) # Execute the given command with arguements


if __name__ == "__main__":
    main()
