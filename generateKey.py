from Crypto.PublicKey import RSA

# Function for generating RSA public private key pair
def generate(name):
    key = RSA.generate(2048) # Generate Key pair
    
    # Store Private Key
    private_key = key.export_key()
    file = open(f'keys/{name}Private.pem','wb')
    file.write(private_key)
    file.close()

    # Store Public Key
    public_key = key.public_key().export_key()
    file_out = open(f"keys/{name}Public.pem", "wb")
    file_out.write(public_key)
    file_out.close()