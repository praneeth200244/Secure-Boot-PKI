import socket
from cryptography.hazmat.primitives import serialization

certificateAuthorityClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
certificateAuthorityClient.connect(('127.0.0.1', 12345))

payLoad = 'Hey I am the Certificate Authority...Please generate my private and public key pair\n'

try:
    while True:
        certificateAuthorityClient.send(payLoad.encode('utf-8'))

        # Receiving private and public key pairs from PKI
        privateKey = certificateAuthorityClient.recv(2048)
        publicKey = certificateAuthorityClient.recv(2048)

        # Storing the private key in a file
        with open('2a__certificate_authority_private_key.pem', 'wb') as private_key_file:
            private_key_file.write(privateKey)

        # Storing the public key in a file
        with open('2b__certificate_authority_public_key.pem', 'wb') as public_key_file:
            public_key_file.write(publicKey)

        print(f"Private Key:\n{privateKey}\n\nPublic Key:\n{publicKey}")
        break
except KeyboardInterrupt:
    print("Error occurred.....!\n")

certificateAuthorityClient.close()
