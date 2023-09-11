import socket
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def csr_signing_request():
    # Create a certificate signing request (CSR)
    subject = x509.Name([
        # Common Name (CN) - Typically the name of the entity
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'tester'),

        # Organization (O) - The name of the organization
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME,
                           u'AutomotiveCyberSecurityOrg'),

        # Organizational Unit (OU) - The department or division within the organization
        x509.NameAttribute(
            x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'SecureBoot'),

        # Country (C) - The country code
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'IN'),

        # State or Province (ST) - The state or province name
        x509.NameAttribute(
            x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'Karnataka'),

        # Locality (L) - The city or locality name
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u'Mysuru'),

        # Email Address (emailAddress) - The email address of the entity
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u'email@tester.com')
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # Convert the CSR to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    return csr_pem


# Connect to the server (Client B)
############################################################################################
clientSocketTester = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverAddressPKICA = ('localhost', 12345)
clientSocketTester.connect(serverAddressPKICA)
###################################################################
payLoad = 'Hey I am the tester...Please generate my private and public key pair\n'
clientSocketTester.send(payLoad.encode('utf-8'))
print("Sent private key request to the PKI server")

privateKey = clientSocketTester.recv(2048)
print("Private key received successfully......!")
print("\nPrivate Key:\n", privateKey, "\n\n")

# Write the received private key to a PEM file
if privateKey:
    with open('testerPrivateKey.pem', 'wb') as private_key_file:
        private_key_file.write(privateKey)
###################################################################

with open('testerPrivateKey.pem', 'rb') as key_file:
    private_key = load_pem_private_key(
        key_file.read(), password=None, backend=default_backend())

# Creating a Certificate Signing Request
csrPEM = csr_signing_request()
clientSocketTester.send(csrPEM)
print("Certificate Signing Request sent to the certificate authority.....")
time.sleep(1)
# Receive the JSON string from the server
response = clientSocketTester.recv(4096).decode('utf-8')
# Parse the JSON string
json_data = json.loads(response)
# Extract the certificate value from the JSON object
signed_cert_pem_str = json_data['certificate']
print("Received signed certificate from the Certificate Authority....")
# Convert the certificate string back to bytes
signed_cert_pem = signed_cert_pem_str.encode('utf-8')
print("\nCertificate:\n", signed_cert_pem)
# Parse the JSON string to a JSON object
# certificate_json = json.loads(received_json_str)

# Specify the file path to store the JSON data
file_path = 'testerCertificate.json'

# Write the JSON object to the file
with open(file_path, 'w') as file:
    json.dump(json_data, file)
##################################################################
clientSocketTester.close()
#################################################################################
