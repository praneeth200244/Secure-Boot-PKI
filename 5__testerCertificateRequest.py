import socket
from cryptography import x509
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import socket
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
import time


# Accessing a private key for the client
with open('1a__tester_private_key.pem', 'rb') as key_file:
    private_key = load_pem_private_key(
        key_file.read(), password=None, backend=default_backend())


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
    x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u'Karnataka'),

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

# Establish a connection to the server
server_address = ('127.0.0.1', 12345)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)
print("Connected to the Certificate Authority Server")

# Send the CSR to the server for signing
client_socket.sendall(csr_pem)
print("Certificate Signing Request sent to the server.....")

# Receive the signed certificate from the server
signed_cert_pem = client_socket.recv(4096)
print("Received signed certificate from the Certificate Authority....")

# Close the connection
client_socket.close()
print("Closing the connection with the Certificate Authority Server.....\n")

# Load the signed certificate
cert = x509.load_pem_x509_certificate(signed_cert_pem, default_backend())

# Load the trusted CA's public key
with open('2b__certificate_authority_public_key.pem', 'rb') as ca_public_key_file:
    ca_public_key = serialization.load_pem_public_key(
        ca_public_key_file.read(), default_backend())

print("Authenticating the certificate....")
time.sleep(1)

# Verify the certificate chain
try:
    received_cert_chain = [cert]
    ca_public_key.verify(

        received_cert_chain[-1].signature,
        received_cert_chain[-1].tbs_certificate_bytes,
        padding.PKCS1v15(),
        received_cert_chain[-1].signature_hash_algorithm
    )
except cryptography.exceptions.InvalidSignature:
    print("Certificate chain verification failed.")
    exit(1)

# Check the certificate's validity period
current_time = datetime.datetime.now()
if cert.not_valid_before > current_time or cert.not_valid_after < current_time:
    print("Certificate is not currently valid.")
    exit(1)


# Certificate authentication is successful
print("Certificate authentication successful.")

# Storing certificate in the file
with open('5__tester_signed_certificate.pem', 'wb') as file:
    file.write(signed_cert_pem)

print("\n************Digital Certificate************\n")
print("Subject:")
for attribute in cert.subject:
    print(f"{attribute.oid._name}: {attribute.value}")
public_key = cert.public_key()
print("Public key: ", public_key)
print()

print("\nIssuer:")

for attribute in cert.issuer:
    print(f"{attribute.oid._name}: {attribute.value}")
print()

print("Serial Number:", cert.serial_number)
print("Not Valid Before:", cert.not_valid_before)
print("Not Valid After:", cert.not_valid_after)

# Access the additional fields (digital signature and algorithm)
extensions = cert.extensions
for extension in extensions:
    if extension.oid.dotted_string == '1.2.3.4.5':
        digital_signature = extension.value.value
    elif extension.oid.dotted_string == '1.2.3.4.6':
        algorithm = extension.value.value.decode()

print("\nDigital Signature:", digital_signature)
print("\nAlgorithm:", algorithm)
print("\n************Digital Certificate************\n")
