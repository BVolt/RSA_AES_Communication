from generateKey import generate
from encrypt import encrypt


def main():
    generate("Alice")
    generate("Bob")
    encrypt("message.txt", "Bob")


if __name__ == "__main__":
    main()