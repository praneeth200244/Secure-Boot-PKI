import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
import time
import mysql.connector

# Create a socket and listen for incoming connections
server_address = ('localhost', 12345)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(server_address)
server_socket.listen(5)
print("Certificate authority server in running up.....!")
time.sleep(1)

print('Server listening on {}:{}'.format(*server_address))

while True:
    # Accept a client connection
    client_socket, client_address = server_socket.accept()
    print('Accepted connection from {}:{}'.format(*client_address))

    # Receive the client's CSR
    csr_pem = client_socket.recv(4096)
    print("Received Certificate Signing Request from the client")

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
            x509.ObjectIdentifier('1.2.3.4.6'), b'SHA256, RSA'
        ),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

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
            (str(client_address), signed_cert_pem.decode('utf-8'))
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

    # Send the signed certificate to the client
    client_socket.sendall(signed_cert_pem)
    print("Certificate sent successfully....!")

    # Close the connection
    client_socket.close()
    print("*******************Request Served Successfully********************************\n\n")
