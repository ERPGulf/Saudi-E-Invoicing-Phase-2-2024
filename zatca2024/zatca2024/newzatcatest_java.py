#========================================== csr code ===================================================================
import datetime
from datetime import datetime
import base64
import datetime
import hashlib
import struct
from lxml import etree
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
class CsrGenerator:
    def __init__(self, config_path):
        self.config = {}
        with open(config_path, 'r') as f:
            for line in f:
                key, value = line.strip().split('=')
                self.config[key] = value

        self.common_name = self.config['csr.common.name']
        self.serial_number = self.config['csr.serial.number']
        self.organization_identifier = self.config['csr.organization.identifier']
        self.organization_unit_name = self.config['csr.organization.unit.name']
        self.organization_name = self.config['csr.organization.name']
        self.country_name = self.config['csr.country.name']
        self.invoice_type = self.config['csr.invoice.type']
        self.location = self.config['csr.location.address']
        self.industry = self.config['csr.industry.business.category']

    def generate_csr(self):
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Include additional attributes in the OU field
        ou_field = f"{self.organization_unit_name}, OID={self.organization_identifier}, InvoiceType={self.invoice_type}, Industry={self.industry}, Location={self.location}"

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.organization_name),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou_field),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.country_name),
        ])).add_extension(
            x509.SubjectAlternativeName([
            ]),
            critical=False
        ).sign(private_key, hashes.SHA256())

        csr_pem = csr.public_bytes(Encoding.PEM)
        private_key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_key_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        csr_base64 = base64.b64encode(csr_pem).decode('utf-8')
        key_base64 = base64.b64encode(private_key_pem).decode('utf-8')
        public_key_base64 = base64.b64encode(public_key_pem).decode('utf-8')

        # print("CSR (PEM):\n", csr_pem.decode('utf-8'))
        print("CSR (Base64):", csr_base64)
        # print("Private Key (Base64):", key_base64)
        # print("Public Key (Base64):", public_key_base64)


        return csr_pem, private_key_pem, public_key_pem,csr_base64
csr_generator = CsrGenerator('sdkcsrconfig.properties')
csr_pem, private_key_pem, public_key_pem,csr_base64 = csr_generator.generate_csr()

# Save the public key to a file
with open('publickeyjava.pem', 'wb') as f:
    f.write(public_key_pem)
with open('privatekeyjava.pem', 'wb') as f:
    f.write(private_key_pem)
with open('csrjava.csr', 'w') as f:
    f.write(csr_base64)

#=============================== transform xml ===================================================================


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
# transform_xml("finalzatcaxml.xml","transformed.xml")


#============================================== certificate ==========================================================
        

def generate_self_signed_certificate(private_key_path, certificate_path, subject_details, validity_days=365):
    # Load the private key
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # Create a subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_details.get("country", "US")),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_details.get("state", "California")),
        x509.NameAttribute(NameOID.LOCALITY_NAME, subject_details.get("locality", "San Francisco")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_details.get("organization", "My Company")),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_details.get("common_name", "mysite.com")),
    ])

    # Generate the certificate
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(subject_details.get("common_name", "mysite.com"))]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    # Save the certificate to a file
    with open(certificate_path, "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))

    print(f"Certificate saved to {certificate_path}")

# Example usage
private_key_path = "/opt/bench4/frappe-bench/sites/privatekeyjava.pem"
certificate_path = "/opt/bench4/frappe-bench/sites/certificatejava.pem"
subject_details = {
    "country": "SA",
    "state": "SAUDI ARABIA",
    "locality": "RIYADH",
    "organization": "My Company",
    "common_name": "myemail@gmail.com"
}

# generate_self_signed_certificate(private_key_path, certificate_path, subject_details)

#======================================= qrcode ==============================================================

# class TLVMessage:
#     def __init__(self, tag, tag_name, value):
#         self.tag = tag
#         self.tag_name = tag_name
#         self.value = value

#     def to_bytes(self):
#         tag_bytes = struct.pack('>B', self.tag)
#         length_bytes = struct.pack('>B', len(self.value))
#         value_bytes = self.value.encode('utf-8')
#         return tag_bytes + length_bytes + value_bytes

# class QRCodeGeneratorService:
#     def generate_qr_code(self, seller_name, vat_registration_number, time_stamp, invoice_total, vat_total, xml_file_path, public_key, digital_signature, is_simplified, certificate_signature):
#         with open(xml_file_path, 'rb') as xml_file:
#             xml_content = xml_file.read()
#         hashed_xml = base64.b64encode(hashlib.sha256(xml_content).digest()).decode('utf-8')

#         tlv_messages = [
#             TLVMessage(1, "Seller Name", seller_name),
#             TLVMessage(2, "VAT Registration Number", vat_registration_number),
#             TLVMessage(3, "Timestamp", time_stamp),
#             TLVMessage(4, "Invoice Total", invoice_total),
#             TLVMessage(5, "VAT Total", vat_total),
#             TLVMessage(6, "Hashed XML", hashed_xml),
#             TLVMessage(7, "Digital Signature", digital_signature),
#             TLVMessage(8, "Public Key", base64.b64encode(public_key).decode('utf-8'))
#         ]

#         if is_simplified:
#             tlv_messages.append(TLVMessage(9, "Certificate Signature", base64.b64encode(certificate_signature).decode('utf-8')))

#         qr_code_bytes = b''.join([msg.to_bytes() for msg in tlv_messages])
#         return base64.b64encode(qr_code_bytes).decode('utf-8')

# generator = QRCodeGeneratorService()
# qr_code_value = generator.generate_qr_code(
#     seller_name="Firoz Ashraf",
#     vat_registration_number="1234567891",
#     time_stamp=datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
#     invoice_total="100.00",
#     vat_total="15.00",
#     xml_file_path="transformed.xml",
#     public_key=public_key_pem,
#     # digital_signature=signature,
#     is_simplified=True,
#     certificate_signature=b"certificate_signature_bytes"
# )

# # print("QR Code Value:", qr_code_value)
#============================================== hash value =======================================================

def get_xml_hash():
    with open("transformed.xml", 'rb') as xml_file:
        xml_content = xml_file.read()
    hash_digest = hashlib.sha256(xml_content).digest()
    base64_hash = base64.b64encode(hash_digest).decode('utf-8')
    return base64_hash  

# ============================================= signing ===========================================================

# from lxml import etree
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import ec

# def sign_xml(qr_code, pih_value):
#     # Load the private key
#     with open("privatekeyjava.pem", 'rb') as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#         )

#     # Load the X.509 certificate
#     with open("certificatejava.pem", 'rb') as cert_file:
#         cert_data = cert_file.read()
#         certificate = x509.load_pem_x509_certificate(cert_data)

#     # Encode the certificate in base64
#     encoded_certificate = base64.b64encode(cert_data).decode('utf-8')

#     # Get issuer name and serial number from the certificate
#     issuer_name = certificate.issuer.rfc4514_string()
#     serial_number = certificate.serial_number

#     # Load the XML content
#     with open("transformed.xml", 'rb') as xml_file:
#         xml_content = xml_file.read()

#     # Parse the XML
#     parser = etree.XMLParser(remove_blank_text=True)
#     tree = etree.fromstring(xml_content, parser)

#     # Canonicalize the XML for signing
#     canonical_xml = etree.tostring(tree, method="c14n")

#     # Compute the digest
#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(canonical_xml)
#     hash_value = digest.finalize()

#     # Sign the digest
#     signature = private_key.sign(
#         hash_value,
#         ec.ECDSA(hashes.SHA256())
#     )

#     encoded_signature = base64.b64encode(signature).decode('utf-8')

#     # Set the signature, certificate, issuer name, and serial number in the XML
#     signature_element = etree.SubElement(tree, "{http://www.w3.org/2000/09/xmldsig#}Signature")
#     signature_value_element = etree.SubElement(signature_element, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
#     signature_value_element.text = encoded_signature

#     key_info_element = etree.SubElement(signature_element, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
#     x509_data_element = etree.SubElement(key_info_element, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
#     x509_certificate_element = etree.SubElement(x509_data_element, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
#     x509_certificate_element.text = encoded_certificate
#     x509_issuer_name_element = etree.SubElement(x509_data_element, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerSerial")
#     x509_issuer_name_element.text = issuer_name
#     x509_serial_number_element = etree.SubElement(x509_issuer_name_element, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber")
#     x509_serial_number_element.text = str(serial_number)

#     # Set the QR code and PIH value in the XML
#     qr_code_element = tree.find('.//cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
#     if qr_code_element is not None:
#         qr_code_element.text = qr_code

#     pih_element = tree.find('.//cac:AdditionalDocumentReference[cbc:ID="PIH"]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
#     if pih_element is not None:
#         pih_element.text = pih_value

#     # Save the signed XML to a file
#     signed_xml_file_path = 'signed_xmljava.xml'
#     with open(signed_xml_file_path, 'wb') as signed_xml_file:
#         signed_xml_file.write(etree.tostring(tree, pretty_print=True))

#     return encoded_signature

# # Example usage
# qr_code =qr_code_value
# pih_value = get_xml_hash()
# signature = sign_xml(qr_code, pih_value)
# print("Digital signature:", signature)

