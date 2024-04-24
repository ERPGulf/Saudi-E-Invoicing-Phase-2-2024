from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import json
import requests
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
import signxml
from lxml import etree
import struct
import hashlib
import datetime
# corrected by Farook the csr

def get_csr_data():
    # Read the properties file
            with open('sdkcsrconfig.properties', 'r') as file:
                lines = [line.strip() for line in file.readlines()]

            # Initialize variables
            csr_common_name = None
            csr_serial_number = None
            csr_organization_identifier = None
            csr_organization_unit_name = None
            csr_organization_name = None
            csr_country_name = None
            csr_invoice_type = None
            csr_location_address = None
            csr_industry_business_category = None

            # Process each line to extract key-value pairs
            for line in lines:
                parts = line.split('=')
                if len(parts) == 2:
                    key, value = parts
                    if key == 'csr.common.name':
                        csr_common_name = value
                    elif key == 'csr.serial.number':
                        csr_serial_number = value
                    elif key == 'csr.organization.identifier':
                        csr_organization_identifier = value
                    elif key == 'csr.organization.unit.name':
                        csr_organization_unit_name = value
                    elif key == 'csr.organization.name':
                        csr_organization_name = value
                    elif key == 'csr.country.name':
                        csr_country_name = value
                    elif key == 'csr.invoice.type':
                        csr_invoice_type = value
                    elif key == 'csr.location.address':
                        csr_location_address = value
                    elif key == 'csr.industry.business.category':
                        csr_industry_business_category = value

            return csr_common_name,csr_serial_number,csr_organization_identifier,csr_organization_unit_name,csr_organization_name,csr_country_name,csr_invoice_type,csr_location_address,csr_industry_business_category


def create_private_key():
        private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_pem

private_key_pem =create_private_key()
def create_csr(portal_type):
    
        csr_common_name,csr_serial_number,csr_organization_identifier,csr_organization_unit_name,csr_organization_name,csr_country_name,csr_invoice_type,csr_location_address,csr_industry_business_category = get_csr_data()
        if portal_type == "sandbox":
            customoid = b"..TESTZATCA-Code-Signing"
        elif portal_type == "simulation":
            customoid = b"..PREZATCA-Code-Signing"
        else:
            customoid = b"..ZATCA-Code-Signing"

        private_key_pem = create_private_key()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
        custom_oid_string = "2.5.9.3.7.1.982.20.2"
        custom_value = customoid
        oid = ObjectIdentifier(custom_oid_string)
        custom_extension = x509.extensions.UnrecognizedExtension(oid, custom_value)
        
        dn = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, csr_common_name),  # csr.common.name
            x509.NameAttribute(NameOID.COUNTRY_NAME, csr_country_name),   # csr.country.name -  has to be two digits 
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, csr_organization_name),   # csr.organization.name
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, csr_organization_unit_name), # csr.organization.unit.name
        ])
        alt_name = x509.SubjectAlternativeName({
            x509.DirectoryName(x509.Name([
                x509.NameAttribute(NameOID.SURNAME, csr_serial_number),   # csr.serial.number-- has to be this format 
                x509.NameAttribute(NameOID.USER_ID, csr_organization_identifier),   # csr.organization.identifier - has to be 13 digit with starting and ending digit 3  
                x509.NameAttribute(NameOID.TITLE, csr_invoice_type),  # csr.invoice.type - has to be 1100
                x509.NameAttribute(NameOID.BUSINESS_CATEGORY, csr_industry_business_category + "/registeredAddress=" + csr_location_address),   # csr.location.address
            ])),
        })

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(dn)
            .add_extension(custom_extension, critical=False)
            .add_extension(alt_name, critical=False)
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        mycsr = csr.public_bytes(serialization.Encoding.PEM)
        base64csr = base64.b64encode(mycsr)
        encoded_string = base64csr.decode('utf-8')
        return private_key_pem,encoded_string

privateKey,csr_string = create_csr("sandbox")
# get_csr_data()
# print(privatekey)
with open('new_csr.csr', 'w') as file:
    file.write(csr_string)
with open('new_private.pem', 'w') as file:
    file.write(privateKey.decode('utf-8'))
# print(csr_string)

def create_csid():
    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
    payload = json.dumps({
    "csr": csr_string
    })
    headers = {
    'accept': 'application/json',
    'OTP': '123345',
    'Accept-Version': 'V2',
    'Content-Type': 'application/json',
    'Cookie': 'TS0106293e=0132a679c07400f36242c054cc5c73a634f51486563baa5cc4d51293c0b38f68d10c82161b3074b1b2dfbe83a1ae5b78f2fd256699'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
    data=json.loads(response.text)
                    # compliance_cert =get_auth_headers(data["binarySecurityToken"],data["secret"])
    concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
    encoded_value = base64.b64encode(concatenated_value.encode()).decode()

    with open(f"certficatejavaaa.pem", 'w') as file:   #attaching X509 certificate
        file.write(base64.b64decode(data["binarySecurityToken"]).decode())
create_csid()

# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import ec, padding
# from cryptography.hazmat.backends import default_backend
# import xml.etree.ElementTree as ET
# import base64

# def load_private_key():
#     with open("new_private.pem", "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#             backend=default_backend()
#         )
#     return private_key

# def sign_data(private_key, data):
#     signature = private_key.sign(
#         data,
#         ec.ECDSA(hashes.SHA256())
#     )
#     return base64.b64encode(signature).decode('utf-8')

# def hash_data(data):
#     digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
#     digest.update(data.encode('utf-8'))
#     return base64.b64encode(digest.finalize()).decode('utf-8')

# def create_signed_xml( xml_path):
#     private_key = load_private_key()
#     tree = ET.parse(xml_path)
#     root = tree.getroot()
#     NS = {
#         'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
#         'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
#     }

#     # Example: Find the Invoice ID to sign
#     invoice_id_element = root.find('.//cbc:ID', NS)
#     if invoice_id_element is not None:
#         invoice_id = invoice_id_element.text
#         invoice_hash = hash_data(invoice_id)
#         digital_signature = sign_data(private_key, invoice_hash.encode('utf-8'))

#         # Embed the digital signature into the XML
#         signature_element = ET.SubElement(root, '{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}Signature')
#         signature_element.text = digital_signature

#         # Save the modified XML
#         tree.write('signed_invoice.xml')
#     else:
#         print("Invoice ID not found.")

# create_signed_xml( 'finalzatcaxml.xml')

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

def transform_xml():
    xml_file_path = "finalzatcaxml.xml"
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

    output_file_path = "transformed.xml"
    with open(output_file_path, 'wb') as output_file:
        output_file.write(xml_content)

# transform_xml()

def create_public_key(private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem

class TLVMessage:
    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def to_bytes(self):
        tag_bytes = struct.pack('>B', self.tag)
        length_bytes = struct.pack('>B', len(self.value))
        if isinstance(self.value, str):
            value_bytes = self.value.encode('utf-8')
        elif isinstance(self.value, bytes):
            value_bytes = self.value
        else:
            raise ValueError("Unsupported value type for TLVMessage")
        return tag_bytes + length_bytes + value_bytes

class QRCodeGeneratorService:
    def generate_qr_code(self, seller_name, vat_registration_number, time_stamp, invoice_total, vat_total, xml_file_path, public_key, digital_signature, is_simplified, certificate_signature):
        with open(xml_file_path, 'rb') as xml_file:
            xml_content = xml_file.read()
        hashed_xml = base64.b64encode(hashlib.sha256(xml_content).digest()).decode('utf-8')

        tlv_messages = [
            TLVMessage(1, seller_name),
            TLVMessage(2, vat_registration_number),
            TLVMessage(3, time_stamp),
            TLVMessage(4, invoice_total),
            TLVMessage(5, vat_total),
            TLVMessage(6, hashed_xml),
            TLVMessage(7, base64.b64encode(digital_signature).decode('utf-8')),
            TLVMessage(8, base64.b64encode(public_key).decode('utf-8'))
        ]

        if is_simplified:
            tlv_messages.append(TLVMessage(9, base64.b64encode(certificate_signature).decode('utf-8')))

        qr_code_bytes = b''.join([msg.to_bytes() for msg in tlv_messages])
        return base64.b64encode(qr_code_bytes).decode('utf-8')

def generate_qr_code_for_invoice(seller_name, vat_registration_number, invoice_total, vat_total, xml_file_path, public_key, digital_signature, is_simplified, certificate_signature):
    generator = QRCodeGeneratorService()
    qr_code_value = generator.generate_qr_code(
        seller_name=seller_name,
        vat_registration_number=vat_registration_number,
        time_stamp=datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        invoice_total=invoice_total,
        vat_total=vat_total,
        xml_file_path=xml_file_path,
        public_key=public_key,
        digital_signature=digital_signature,
        is_simplified=is_simplified,
        certificate_signature=certificate_signature
    )
    return qr_code_value

# Example usage
qr_code_value = generate_qr_code_for_invoice(
    seller_name="Firoz Ashraf",
    vat_registration_number="1234567891",
    invoice_total="100.00",
    vat_total="15.00",
    xml_file_path="transformed.xml",
    public_key=create_public_key(private_key_pem),
    digital_signature=b"digital_signature_bytes",  # Replace with actual digital signature bytes
    is_simplified=True,
    certificate_signature=b"certificate_signature_bytes"  # Replace with actual certificate signature bytes
)
print("QR Code Value:", qr_code_value)


# def get_xml_hash():
    # with open("transformed.xml", 'rb') as xml_file:
    #     xml_content = xml_file.read()
    # hash_digest = hashlib.sha256(xml_content).digest()
    # base64_hash = base64.b64encode(hash_digest).decode('utf-8')
    # return base64_hash  


from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree
import base64
def sign_xml():
                with open("new_private.pem", 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                    )

                with open("certficatejavaaa.pem", 'r') as file:
                    certificate_content = file.read()
                    # print(certificate_content)
                cert_path = 'certificatejavaa2.pem'
                with open(cert_path, "w") as file:
                    file.write("-----BEGIN CERTIFICATE-----\n")
                    file.write("\n".join(certificate_content[i:i+64] for i in range(0, len(certificate_content), 64)))
                    file.write("\n-----END CERTIFICATE-----\n")
                print("Certificate saved to certificatejavaa2.pem")
                with open("certificatejavaa2.pem", 'rb') as cert_file:
                    cert_data = cert_file.read()
                certificate = x509.load_pem_x509_certificate(cert_data)
                direct_certificate_data = certificate_content
                # print(direct_certificate_data)
                digest = hashes.Hash(hashes.SHA256())
                digest.update(certificate.public_bytes(serialization.Encoding.DER))
                hashed_certificate = digest.finalize()
                encoded_hashed_certificate = base64.b64encode(hashed_certificate).decode('utf-8')
                # print(encoded_hashed_certificate)
                issuer_name = certificate.issuer.rfc4514_string()
                serial_number = certificate.serial_number

                with open("transformed.xml", 'rb') as xml_file:
                    xml_content = xml_file.read()
                    
                parser = etree.XMLParser(remove_blank_text=True)
                tree = etree.fromstring(xml_content, parser)
                canonical_xml = etree.tostring(tree, method="c14n")

                digest = hashes.Hash(hashes.SHA256())
                digest.update(canonical_xml)
                hash_value = digest.finalize()

                signature = private_key.sign(
                    hash_value,
                    ec.ECDSA(hashes.SHA256())
                )
                encoded_signature = base64.b64encode(signature).decode('utf-8')

                properties_element = tree.find('.//xades:SignedProperties', namespaces={'xades': 'http://uri.etsi.org/01903/v1.3.2#'})
                linearized_properties = etree.tostring(properties_element, method="c14n", exclusive=True, with_comments=False).decode('utf-8').replace(' ', '')
                digest = hashes.Hash(hashes.SHA256())
                digest.update(linearized_properties.encode('utf-8'))
                hashed_properties = digest.finalize()
                encoded_hashed_properties = base64.b64encode(hashed_properties).decode('utf-8')
                # print(encoded_hashed_properties)

                # print("Hashed Properties (SHA-256):", hashed_properties.hex())
                signed_properties_element = tree.find('.//xades:SignedProperties', namespaces={'xades': 'http://uri.etsi.org/01903/v1.3.2#'})
                linearized_signed_properties = etree.tostring(signed_properties_element, method="c14n", exclusive=True, with_comments=False).decode('utf-8').replace(' ', '')
                digest = hashes.Hash(hashes.SHA256())
                digest.update(linearized_signed_properties.encode('utf-8'))
                hashed_signed_properties = digest.finalize()

                encoded_hashed_signed_properties = base64.b64encode(hashed_signed_properties).decode('utf-8')
                digest_value_element = tree.find('.//ds:Reference[@URI="#xadesSignedProperties"]/ds:DigestValue', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                if digest_value_element is not None:
                    digest_value_element.text = encoded_hashed_signed_properties


                signature_value_element = tree.find('.//ds:SignatureValue', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                if signature_value_element is not None:
                    signature_value_element.text = encoded_signature

                x509_data_element = tree.find('.//ds:X509Data', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                if x509_data_element is not None:
                    x509_certificate_element = etree.SubElement(x509_data_element, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
                    x509_certificate_element.text = direct_certificate_data

                issuer_serial_element = tree.find('.//xades:IssuerSerial', namespaces={'xades': 'http://uri.etsi.org/01903/v1.3.2#', 'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                if issuer_serial_element is not None:
                    for element in issuer_serial_element.findall('{http://www.w3.org/2000/09/xmldsig#}X509IssuerName'):
                        issuer_serial_element.remove(element)
                    for element in issuer_serial_element.findall('{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber'):
                        issuer_serial_element.remove(element)

                    issuer_name_element = etree.SubElement(issuer_serial_element, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName")
                    issuer_name_element.text = issuer_name

                    serial_number_element = etree.SubElement(issuer_serial_element, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber")
                    serial_number_element.text = str(serial_number)


                signing_time_element = tree.find('.//xades:SigningTime', namespaces={'xades': 'http://uri.etsi.org/01903/v1.3.2#'})
                if signing_time_element is not None:
                    signing_time_element.text = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

                digest_value_element = tree.find('.//xades:CertDigest/ds:DigestValue', namespaces={'xades': 'http://uri.etsi.org/01903/v1.3.2#', 'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                if digest_value_element is not None:
                    digest_value_element.text = encoded_hashed_certificate

                qr_code = qr_code_value
                qr_code_element = tree.find('.//cac:AdditionalDocumentReference[cbc:ID="QR"]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
                if qr_code_element is not None:
                    qr_code_element.text = qr_code

                with open("signed_transformed.xml", "wb") as f:
                    f.write(etree.tostring(tree, pretty_print=True))
                print("XML signed successfully")




import xml.etree.ElementTree as ET

def process_xml(file_path):
    # Read the XML content
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read().lstrip()  # Remove leading whitespace

    # Remove Byte Order Mark (BOM) if present
    if content.startswith("\ufeff"):
        content = content[1:]

    # Check XML well-formedness
    try:
        tree = ET.fromstring(content)
        print("XML is well-formed.")
    except ET.ParseError as e:
        print(f"XML is not well-formed: {e}")
        return

    # Save the corrected XML document
    with open("corrected_" + file_path, "w", encoding="utf-8") as file:
        file.write(content)
    print(f"Corrected XML saved as 'corrected_{file_path}'")

sign_xml()   
process_xml("signed_transformed.xml")

