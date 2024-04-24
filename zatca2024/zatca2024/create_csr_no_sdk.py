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
# create_csid()

