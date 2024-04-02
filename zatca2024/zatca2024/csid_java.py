from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
import base64
# Read the configuration file
config_file = "sdkcsrconfig.properties"
config = {}
with open(config_file, "r") as file:
    for line in file:
        key, value = line.strip().split("=")
        config[key] = value

# Generate a key pair
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Create a CSR
csr = x509.CertificateSigningRequestBuilder()

# Set the subject of the CSR
csr = csr.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, config.get("csr.country.name")),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.get("csr.location.address")),
    x509.NameAttribute(NameOID.LOCALITY_NAME, config.get("csr.location.address")),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get("csr.organization.name")),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.get("csr.organization.unit.name")),
    x509.NameAttribute(NameOID.COMMON_NAME, config.get("csr.common.name")),
]))

# Add extensions (Note: Adjust these as per your actual extension requirements)
csr = csr.add_extension(
    x509.SubjectAlternativeName([x509.DNSName(config.get("csr.common.name"))]),
    critical=False,
)

# Sign the CSR
csr = csr.sign(key, hashes.SHA256())

# Create the CSR in PEM format
csr_pem = csr.public_bytes(Encoding.PEM)

# Base64 encode the CSR
csr_base64 = base64.b64encode(csr_pem).decode()

# Print the results
print("Private Key:")
print(key.private_bytes(
    Encoding.PEM,
    PrivateFormat.PKCS8,
    NoEncryption()
).decode())

print("CSR:")
print(csr_pem.decode())

print("Base64 Encoded CSR:")
print(csr_base64)
