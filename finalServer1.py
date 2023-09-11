import base64
import threading
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import time
import json
import re


def generationStorageDistributionOfKeys(clientAddress):
    # Generating key pair using RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    print(
        f"Keys generated successfully for the client with address-{clientAddress}")

    print("Keys generated:\n")
    print(private_key, "\n")
    print("\n", public_key, "\n")

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
    return private_pem


def generationStorageDistributionCertificates(clientAddress, csr_pem):
    # Load the client's CSR
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Accessing private key of the server
    with open('2a__certificate_authority_private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend())

    print("Generating Certificate....")
    time.sleep(1)

    # Create a certificate for the client
    subject = csr.subject
    issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,
                           u'JSS Certificate Authority'),
        x509.NameAttribute(
            x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'Karnataka'),
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'IN'),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'Mysuru')
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )

    # Create a hash of the client's information
    cert_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    cert_hash.update(csr_pem)
    hash_value = cert_hash.finalize()

    # Sign the hash with the private key
    signature = private_key.sign(
        hash_value,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Add the signature and algorithm information to the certificate
    cert = cert.add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier('1.2.3.4.5'), signature
        ),
        critical=False
    ).add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier('1.2.3.4.6'), b'SHA256'
        ),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    print(
        f"Certificate generated successfully for the client with address-{clientAddress}")

    # Convert the signed certificate to PEM format
    signed_cert_pem = cert.public_bytes(serialization.Encoding.PEM)

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
        CREATE TABLE IF NOT EXISTS cerificates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            clientAddress TEXT NOT NULL,
            certificate TEXT NOT NULL
        )
        """
        )

        # Insert the keys into the table
        cursor.execute(
            """
        INSERT INTO cerificates(clientAddress, certificate)
        VALUES ( % s, % s)
        """,
            (str(clientAddress), signed_cert_pem.decode('utf-8'))
        )

        # Commit the transaction
        conn.commit()
        print("Cerificate stored successfully!")

    except mysql.connector.Error as error:
        print("Couldn't store the certificate...!:", error)
        conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # Return the signed certificate to the client
    return signed_cert_pem


# Handle client requests
payLoad = 'Hey I am the tester...Please generate my private and public key pair\n'
# Set up the server socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverAddress = ('localhost', 12345)
serverSocket.bind(serverAddress)
serverSocket.listen(1)
print("Server is listening...")
clientSocket, clientAddress = serverSocket.accept()
i = 1
while i <= 2:
    # Accept a new client connection
    print(clientSocket)
    print(f"New connection from: {clientAddress}")

    # Receive data from the client
    receivedRequest = clientSocket.recv(4096)

    if receivedRequest.decode('utf-8') == payLoad:
        try:
            privateKeyBytes = generationStorageDistributionOfKeys(
                clientAddress)
            clientSocket.send(privateKeyBytes)
            print("Private key sent to the client")
        except:
            print("Error.....\n")

    else:
        print("\n\n", "Request:\n", receivedRequest, "\n\n")
        print("Received Certificate Signing Request from the client")

        signed_cert_pem = generationStorageDistributionCertificates(
            clientAddress, receivedRequest)

        # Convert signed_cert_pem to a JSON-compatible format
        signed_cert_pem_str = signed_cert_pem.decode('utf-8')
        print("\nFinal Certificate:\n", signed_cert_pem, "\n\n")
        # Create a JSON object
        json_response = {'certificate': signed_cert_pem_str}
        # Serialize the JSON object to a string
        json_string = json.dumps(json_response)
        clientSocket.send(json_string.encode('utf-8'))
        print("Certificate sent successfully....!")

    print("**************************************Request Served*********************************")

    i += 1
    # Close the client socket
    # clientSocket.close()
    # print("Hi")
