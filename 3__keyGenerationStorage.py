# import socket

# serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# serverSocket.bind(('127.0.0.1', 12345))
# serverSocket.listen(10)

# while True:
#     print("The PKI Server is running....!\n")
#     clientSocket, clientAddress = serverSocket.accept()
#     print(f"Client connected from {clientAddress}")

#     while True:
#         clientRequest = clientSocket.recv(2048)
#         if not clientRequest or clientRequest.decode('utf-8') == 'END':
#             break
#         print(
#             f"Request received from the client: {clientRequest.decode('utf-8')}")
#         try:
#             # Generation and storage of key-pairs
#             clientSocket.send(
#                 bytes('Don\'t worry, I will generate your keys', 'utf-8'))
#         except:
#             print("Glitch.....\n")
#     clientSocket.close()

# serverSocket.close()

##################################################################################################################
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import mysql.connector
import time
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generationStorageKeys(clientAddress):
    # Generating key pair using RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    print(
        f"Keys generated successfully for the client with address-{clientAddress}")

    # Convert keys to Privacy-Enhanced Mail(PEM) format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(private_pem, "\n")
    print(public_pem, "\n")

    # Storing of keys in the database
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="PlAcE@123#MeNt",
            database="PKI_BOSCH"
        )
        cursor = conn.cursor()

        # Creating a table to store the keys
        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS rsa_keys (
            id INT AUTO_INCREMENT PRIMARY KEY,
            clientAddress TEXT NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
        """
        )

        # Insert the keys into the table
        cursor.execute(
            """
        INSERT INTO rsa_keys (clientAddress, private_key, public_key)
        VALUES (%s, %s, %s)
        """,
            (str(clientAddress), private_pem.decode(
                'utf-8'), public_pem.decode('utf-8'))
        )

        # Commit the transaction
        conn.commit()
        print("Keys stored successfully!")

    except mysql.connector.Error as error:
        print("Couldn't store the keys...!:", error)

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # return (private_key, public_key)
    return (private_pem, public_pem)


serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(('127.0.0.1', 12345))
serverSocket.listen(10)

while True:
    time.sleep(1)
    print("The PKI Server is running....!\n")
    time.sleep(1)
    clientSocket, clientAddress = serverSocket.accept()
    print(f"Client connected from {clientAddress}")

    while True:
        clientRequest = clientSocket.recv(2048)
        if not clientRequest or clientRequest.decode('utf-8') == 'END':
            break
        print(
            f"Request received from the client: {clientRequest.decode('utf-8')}")
        try:
            # Generation and storage of key pairs
            privateKeyBytes, publicKeyBytes = generationStorageKeys(
                clientAddress)

            clientSocket.send(privateKeyBytes)
            clientSocket.send(publicKeyBytes)
        except:
            print("Error.....\n")
    clientSocket.close()
    print("**************************************Request Served*********************************")


serverSocket.close()
