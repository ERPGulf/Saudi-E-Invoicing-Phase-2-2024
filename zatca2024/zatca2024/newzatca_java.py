import base64
import datetime
import hashlib
import struct
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from lxml import etree
import requests
import datetime
from datetime import datetime
def fetch_content_from_url(url):
    """Fetches content from a specified URL."""
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    else:
        raise Exception(f"Failed to fetch content from {url}")

def apply_xsl_transformation(xml_input_bytes, xsl_content_bytes):
    """Applies an XSL transformation to an XML input."""
    xml_tree = etree.fromstring(xml_input_bytes)
    xsl_tree = etree.fromstring(xsl_content_bytes)
    transform = etree.XSLT(xsl_tree)
    result_tree = transform(xml_tree)
    return etree.tostring(result_tree, pretty_print=True)

def transform_xml(xml_file_path, output_file_path):
    base_url = "https://raw.githubusercontent.com/y2n0s/ZatcaDemo/8211c298125b06fa766a12836418d9428d2ba63a/EInvoiceKSADemo.Helpers/Zatca/Files/Data/"
    steps = [
        ("removeElements.xsl", None),
        ("addUBLElement.xsl", None),
        (None, ("UBL-TO-BE-REPLACED", "ubl.xml")),
        ("addQRElement.xsl", None),
        (None, ("QR-TO-BE-REPLACED", "qr.xml")),
        ("addSignatureElement.xsl", None),
        (None, ("SIGN-TO-BE-REPLACED", "signature.xml")),
    ]

    with open(xml_file_path, 'rb') as xml_file:
        xml_content = xml_file.read()

    for step in steps:
        xsl_file, placeholder = step
        if xsl_file:
            xsl_url = base_url + xsl_file
            xsl_content = fetch_content_from_url(xsl_url)
            xml_content = apply_xsl_transformation(xml_content, xsl_content)
        elif placeholder:
            placeholder_text, replacement_file = placeholder
            replacement_url = base_url + replacement_file
            replacement_content = fetch_content_from_url(replacement_url)
            xml_content = xml_content.replace(placeholder_text.encode(), replacement_content)

    with open(output_file_path, 'wb') as output_file:
        output_file.write(xml_content)

class TLVMessage:
    def __init__(self, tag, tag_name, value):
        self.tag = tag
        self.tag_name = tag_name
        self.value = value

    def to_bytes(self):
        tag_bytes = struct.pack('>B', self.tag)
        length_bytes = struct.pack('>B', len(self.value))
        value_bytes = self.value.encode('utf-8')
        return tag_bytes + length_bytes + value_bytes

class QRCodeGeneratorService:
    def generate_qr_code(self, seller_name, vat_registration_number, time_stamp, invoice_total, vat_total, xml_file_path, public_key, digital_signature, is_simplified, certificate_signature):
        with open(xml_file_path, 'rb') as xml_file:
            xml_content = xml_file.read()
        hashed_xml = base64.b64encode(hashlib.sha256(xml_content).digest()).decode('utf-8')

        tlv_messages = [
            TLVMessage(1, "Seller Name", seller_name),
            TLVMessage(2, "VAT Registration Number", vat_registration_number),
            TLVMessage(3, "Timestamp", time_stamp),
            TLVMessage(4, "Invoice Total", invoice_total),
            TLVMessage(5, "VAT Total", vat_total),
            TLVMessage(6, "Hashed XML", hashed_xml),
            TLVMessage(7, "Digital Signature", digital_signature),
            TLVMessage(8, "Public Key", base64.b64encode(public_key).decode('utf-8'))
        ]

        if is_simplified:
            tlv_messages.append(TLVMessage(9, "Certificate Signature", base64.b64encode(certificate_signature).decode('utf-8')))

        qr_code_bytes = b''.join([msg.to_bytes() for msg in tlv_messages])
        return base64.b64encode(qr_code_bytes).decode('utf-8')

def generate_private_key_pem(file_name):
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    with open(file_name, 'wb') as pem_file:
                pem_file.write(pem)

    print(f"Private key saved to {file_name}")
    return private_key

def sign_ecdsa(private_key, message):
    return private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

def get_digital_signature(xml_file_path, private_key_pem):
    with open(xml_file_path, 'rb') as xml_file:
        xml_content = xml_file.read()

    private_key = load_pem_private_key(
        private_key_pem,
        password=None,
    )
    signature = sign_ecdsa(private_key, xml_content)
    return base64.b64encode(signature).decode('utf-8')

def get_xml_hash(xml_file_path):
    with open(xml_file_path, 'rb') as xml_file:
        xml_content = xml_file.read()
    hash_digest = hashlib.sha256(xml_content).digest()
    base64_hash = base64.b64encode(hash_digest).decode('utf-8')
    return base64_hash  

from datetime import datetime, timedelta

def generate_self_signed_certificate(file_name_prefix):
    # Generate a private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "RIYAD"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "AIRPORT ROAD"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ERPGULF"),
        x509.NameAttribute(NameOID.COMMON_NAME, "myemail@gmail.com"),
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now()  # Use datetime.datetime.now()
    ).not_valid_after(
        # The certificate will be valid for 10 days
        datetime.now() + timedelta(days=10)  # Use datetime.datetime.now()
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(private_key, hashes.SHA256())

    # Write the certificate and private key to disk
    cert_file = f"{file_name_prefix}_certificate.pem"
    key_file = f"{file_name_prefix}_private_key.pem"

    with open(cert_file, "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))

    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

    return cert_file, key_file


def sign_xml(xml_file_path, private_key_pem, certificate_pem, qr_code, pih_value):
    # Load the private key
    with open(private_key_pem, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Load the X.509 certificate
    with open(certificate_pem, 'rb') as cert_file:
        cert_data = cert_file.read()
        certificate = x509.load_pem_x509_certificate(cert_data)

    # Encode the certificate in base64
    encoded_certificate = base64.b64encode(cert_data).decode('utf-8')

    # Get issuer name and serial number from the certificate
    issuer_name = certificate.issuer.rfc4514_string()
    serial_number = certificate.serial_number

    # Load the XML content
    with open(xml_file_path, 'rb') as xml_file:
        xml_content = xml_file.read()

    # Parse the XML
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.fromstring(xml_content, parser)

    # Canonicalize the XML for signing
    canonical_xml = etree.tostring(tree, method="c14n")

    # Compute the digest
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical_xml)
    hash_value = digest.finalize()

   
    signature = private_key.sign(
        hash_value,
        ec.ECDSA(hashes.SHA256())
    )

    encoded_signature = base64.b64encode(signature).decode('utf-8')

    # Set the signature, certificate, issuer name, and serial number in the XML
    signature_value_element = tree.find('.//ds:SignatureValue', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
    if signature_value_element is not None:
        signature_value_element.text = encoded_signature

    x509_certificate_element = tree.find('.//ds:X509Certificate', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
    if x509_certificate_element is not None:
        x509_certificate_element.text = encoded_certificate

    x509_issuer_name_element = tree.find('.//ds:X509IssuerName', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
    if x509_issuer_name_element is not None:
        x509_issuer_name_element.text = issuer_name

    x509_serial_number_element = tree.find('.//ds:X509SerialNumber', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
    if x509_serial_number_element is not None:
        x509_serial_number_element.text = str(serial_number)

 
    qr_code_element = tree.find('.//cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
    if qr_code_element is not None:
        qr_code_element.text = qr_code

    pih_element = tree.find('.//cac:AdditionalDocumentReference[cbc:ID="PIH"]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
    if pih_element is not None:
        pih_element.text = pih_value

   
    signed_xml_file_path = 'signed_' + xml_file_path
    with open(signed_xml_file_path, 'wb') as signed_xml_file:
        signed_xml_file.write(etree.tostring(tree, pretty_print=True))

    return encoded_signature


xml_file_path = 'finalzatcaxml.xml'
output_file_path = 'transformed.xml'
transform_xml(xml_file_path, output_file_path)
private_key = generate_private_key_pem('private_key.pem')
with open('private_key.pem', 'rb') as pem_file:
    private_key_pem = pem_file.read()
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as pem_file:
    pem_file.write(public_key_pem)
digital_signature = get_digital_signature(output_file_path, private_key_pem)
generator = QRCodeGeneratorService()
qr_code_value = generator.generate_qr_code(
    seller_name="Firoz Ashraf",
    vat_registration_number="1234567891",
    time_stamp=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
    invoice_total="100.00",
    vat_total="15.00",
    xml_file_path=output_file_path,
    public_key=public_key_pem,
    digital_signature=digital_signature,
    is_simplified=True,
    certificate_signature=b"certificate_signature_bytes"
)
print("QR Code Value:", qr_code_value)
hash_value = get_xml_hash(output_file_path)
print("Hash value:", hash_value)
cert_file, key_file = generate_self_signed_certificate("my_cert")
signature = sign_xml(output_file_path, key_file, cert_file, qr_code_value,hash_value)
print("Signature:", signature)
