# import base64
# import datetime
# import hashlib
# import json
# import requests
# import struct
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import ec
# from lxml import etree

# # Read CSR data from the properties file
# def get_csr_data():
#     with open('sdkcsrconfig.properties', 'r') as file:
#         lines = [line.strip() for line in file.readlines()]

#     csr_data = {}
#     for line in lines:
#         key, value = line.split('=')
#         csr_data[key] = value

#     return csr_data

# # Generate a private key
# def create_private_key():
#     private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
#     private_key_pem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     return private_key, private_key_pem

# # Create a CSR
# def create_csr(portal_type):
#     csr_data = get_csr_data()

#     if portal_type == "sandbox":
#         custom_oid = "2.5.9.3.7.1.982.20.2..TESTZATCA-Code-Signing"
#     elif portal_type == "simulation":
#         custom_oid = "2.5.9.3.7.1.982.20.2..PREZATCA-Code-Signing"
#     else:
#         custom_oid = "2.5.9.3.7.1.982.20.2..ZATCA-Code-Signing"

#     private_key, private_key_pem = create_private_key()
#     builder = x509.CertificateSigningRequestBuilder()
#     builder = builder.subject_name(x509.Name([
#         x509.NameAttribute(x509.NameOID.COMMON_NAME, csr_data['csr.common.name']),
#         x509.NameAttribute(x509.NameOID.COUNTRY_NAME, csr_data['csr.country.name']),
#         x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, csr_data['csr.organization.name']),
#         x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, csr_data['csr.organization.unit.name']),
#     ]))

#     builder = builder.add_extension(
#         x509.SubjectAlternativeName([
#             x509.OtherName(x509.ObjectIdentifier(custom_oid), b""),
#         ]),
#         critical=False
#     )

#     csr = builder.sign(private_key, hashes.SHA256(), default_backend())
#     csr_pem = csr.public_bytes(serialization.Encoding.PEM)

#     return private_key_pem, csr_pem

# # Generate a QR code for the invoice
# def generate_qr_code_for_invoice(seller_name, vat_registration_number, invoice_total, vat_total, xml_file_path, public_key_pem, digital_signature):
#     with open(xml_file_path, 'rb') as xml_file:
#         xml_content = xml_file.read()

#     hashed_xml = base64.b64encode(hashlib.sha256(xml_content).digest()).decode('utf-8')

#     tlv_messages = [
#         (1, seller_name),
#         (2, vat_registration_number),
#         (3, datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")),
#         (4, invoice_total),
#         (5, vat_total),
#         (6, hashed_xml),
#         (7, base64.b64encode(digital_signature).decode('utf-8')),
#         (8, base64.b64encode(public_key_pem).decode('utf-8'))
#     ]

#     qr_code_bytes = b''
#     for tag, value in tlv_messages:
#         tag_bytes = struct.pack('>B', tag)
#         length_bytes = struct.pack('>B', len(value.encode('utf-8')))
#         value_bytes = value.encode('utf-8')
#         qr_code_bytes += tag_bytes + length_bytes + value_bytes

#     return base64.b64encode(qr_code_bytes).decode('utf-8')

# # Example usage
# private_key_pem, csr_pem = create_csr("sandbox")
# public_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend()).public_key()
# public_key_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

# # Replace these with actual values
# digital_signature = b"example_signature"

# qr_code_value = generate_qr_code_for_invoice(
#     seller_name="Example Seller",
#     vat_registration_number="123456789",
#     invoice_total="100.00",
#     vat_total="15.00",
#     xml_file_path="example.xml",
#     public_key_pem=public_key_pem,
#     digital_signature=digital_signature
# )

# print("QR Code Value:", qr_code_value)
import frappe
import os
import re
frappe.init(site="prod.erpgulf.com")
frappe.connect()
def _execute_in_shell(cmd, verbose=False, low_priority=False, check_exit_code=False):
                # using Popen instead of os.system - as recommended by python docs
                import shlex
                import tempfile
                from subprocess import Popen
                env_variables = {"MY_VARIABLE": "some_value", "ANOTHER_VARIABLE": "another_value"}
                if isinstance(cmd, list):
                    # ensure it's properly escaped; only a single string argument executes via shell
                    cmd = shlex.join(cmd)
                    # process = subprocess.Popen(command_sign_invoice, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env_variables)               
                with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                    kwargs = {"shell": True, "stdout": stdout, "stderr": stderr}
                    if low_priority:
                        kwargs["preexec_fn"] = lambda: os.nice(10)
                    p = Popen(cmd, **kwargs)
                    exit_code = p.wait()
                    stdout.seek(0)
                    out = stdout.read()
                    stderr.seek(0)
                    err = stderr.read()
                failed = check_exit_code and exit_code

                if verbose or failed:
                    if err:
                        frappe.msgprint(err)
                    if out:
                        frappe.msgprint(out)
                if failed:
                    raise Exception("Command failed")
                return err, out

def remove_key_headers(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    # Filter out the lines that contain the BEGIN/END headers
    key_lines = [line.strip() for line in lines if "-----BEGIN EC PRIVATE KEY-----" not in line and "-----END EC PRIVATE KEY-----" not in line]
    
    # Join the remaining lines to form the complete key content
    key_content = ''.join(key_lines)
    
    # Save the modified content back to a file or use it directly in your application
    with open('new_private.pem', 'w') as file:
        file.write(key_content)

# Call the function with the path to your original key file
remove_key_headers('new_private.pem')

def sign_invoice():
                try:
                    settings=frappe.get_doc('Zatca setting')
                    xmlfile_name = 'finalzatcaxml.xml'
                    signed_xmlfile_name = 'sdsignjava.xml'
                    SDK_ROOT= settings.sdk_root
                    sdk_config_file = 'configjava.json'
                    path_string = f"export SDK_ROOT={SDK_ROOT} && export FATOORA_HOME=$SDK_ROOT/Apps && export SDK_CONFIG={sdk_config_file} && export PATH=$PATH:$FATOORA_HOME &&  "
                    
                    command_sign_invoice = path_string  + f'fatoora -sign -invoice {xmlfile_name} -signedInvoice {signed_xmlfile_name}'
                    print(command_sign_invoice)
                except Exception as e:
                 print("While signing invoice An error occurred, inside sign_invoice : " + str(e))
                try:
                    err,out = _execute_in_shell(command_sign_invoice)
                    
                    
                    match = re.search(r'ERROR', err.decode("utf-8"))
                    if match:
                        frappe.throw(err)

                    match = re.search(r'ERROR', out.decode("utf-8"))
                    if match:
                        frappe.throw(out)
                    
                    match = re.search(r'INVOICE HASH = (.+)', out.decode("utf-8"))
                    if match:
                        invoice_hash = match.group(1)
                        # frappe.msgprint("Xml file signed successfully and formed the signed xml invoice hash as : " + invoice_hash)
                        return signed_xmlfile_name , path_string
                    else:
                        frappe.throw(err,out)
                except Exception as e:
                    frappe.throw("An error occurred sign invoice : " + str(e))
sign_invoice()              

import lxml.etree as ET
import xmlsec

def load_xml(filename):
    return ET.parse(filename)

def modify_xml(tree):
    root = tree.getroot()
    qr_elements = root.findall('.//QRCode')
    for qr in qr_elements:
        qr.text = 'new QR code value'

def create_signature_template(tree):
    signature_node = xmlsec.template.create(tree, xmlsec.constants.TransformExclC14N, xmlsec.constants.TransformRsaSha256)
    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(key_info)
    return signature_node

def sign_xml(tree, private_key_file, cert_file):
    root = tree.getroot()
    signature_node = create_signature_template(tree)
    root.append(signature_node)

    ctx = xmlsec.SignatureContext()
    try:
        print("Attempting to load private key from:", private_key_file)
        key = xmlsec.Key.from_file(private_key_file, xmlsec.constants.KeyDataFormatPem)
        key.load_cert_from_file(cert_file, xmlsec.constants.KeyDataFormatPem)
    except xmlsec.Error as e:
        print(f"Failed to load private key or certificate: {e}")
        raise

    ctx.key = key
    ctx.sign(signature_node)

def save_xml(tree, output_filename):
    tree.write(output_filename, pretty_print=True, xml_declaration=True, encoding='utf-8')

input_xml_path = 'finalzatcaxml.xml'
private_key_path = 'new_private.pem'
cert_path = 'certficatejavaaa.pem'
output_xml_path = 'signed_outputjava.xml'

try:
    xml_tree = load_xml(input_xml_path)
    modify_xml(xml_tree)
    sign_xml(xml_tree, private_key_path, cert_path)
    save_xml(xml_tree, output_xml_path)
    print("XML signing completed successfully and saved to:", output_xml_path)
except Exception as e:
    print("An error occurred:", e)
# from lxml import etree
# from OpenSSL import crypto
# import base64
# import hashlib
# import qrcode
# from io import BytesIO

# # Define the namespaces explicitly
# namespaces = {
#     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#     'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
#     'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'
# }

# # Utilities
# def canonicalize_xml(xml_element):
#     return etree.tostring(xml_element, method='c14n')

# def hash_base64(data, hash_type='sha256'):
#     hash_obj = hashlib.new(hash_type)
#     hash_obj.update(data)
#     return base64.b64encode(hash_obj.digest()).decode('utf-8')

# # XML Processing
# def get_pure_invoice_string(xml_data):
#     root = etree.XML(xml_data)
#     xpath_query = "//ext:UBLExtensions | //cac:Signature | //cac:AdditionalDocumentReference[cbc:ID='QR']"
#     for elem in root.xpath(xpath_query, namespaces=namespaces):
#         elem.getparent().remove(elem)
#     return canonicalize_xml(root)

# # Hashing
# def get_invoice_hash(xml_data):
#     pure_xml = get_pure_invoice_string(xml_data)
#     return hash_base64(pure_xml)  # Corrected line

# # Certificate Hash
# def get_certificate_hash(cert_pem):
#     x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
#     cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)
#     return hash_base64(cert_der)

# # Digital Signature
# def create_invoice_digital_signature(invoice_hash, private_key_pem):
#     private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
#     sign = crypto.sign(private_key, base64.b64decode(invoice_hash), 'sha256')
#     return base64.b64encode(sign).decode('utf-8')

# # Certificate Information
# def get_certificate_info(cert_pem):
#     x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
#     issuer = x509.get_issuer()
#     issuer_str = ', '.join([f"{name.decode()}={value.decode()}" for name, value in issuer.get_components()])
#     serial_number = x509.get_serial_number()
#     public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, x509.get_pubkey())
#     cert_hash = get_certificate_hash(cert_pem)
#     return {
#         'hash': cert_hash,
#         'issuer': issuer_str,
#         'serial_number': str(serial_number),
#         'public_key': public_key.decode('utf-8')
#     }

# # QR Code Generation
# def generate_qr_code(data):
#     qr = qrcode.QRCode(
#         version=1,
#         error_correction=qrcode.constants.ERROR_CORRECT_L,
#         box_size=10,
#         border=4,
#     )
#     qr.add_data(data)
#     qr.make(fit=True)
#     img = qr.make_image(fill='black', back_color='white')
#     buffered = BytesIO()
#     img.save(buffered, format="JPEG")
#     return base64.b64encode(buffered.getvalue()).decode('utf-8')

# # Main signing function with output file generation
# def generate_signed_xml_string(file_path, cert_path, key_path):
#     with open(file_path, 'rb') as file:
#         xml_data = file.read()
#     with open(cert_path, 'rb') as file:
#         cert_pem = file.read()
#     with open(key_path, 'rb') as file:
#         private_key_pem = file.read()

#     invoice_hash = get_invoice_hash(xml_data)
#     cert_info = get_certificate_info(cert_pem)
#     digital_signature = create_invoice_digital_signature(invoice_hash, private_key_pem)
    
#     # Generate QR code data
#     qr_data = f"Invoice Hash: {invoice_hash}, Signature: {digital_signature}"
#     qr_code = generate_qr_code(qr_data)
    
#     # Assuming we're modifying the XML here
#     signed_xml_content = f"""<SignedInvoice>
# <InvoiceHash>{invoice_hash}</InvoiceHash>
# <DigitalSignature>{digital_signature}</DigitalSignature>
# <QrCode>{qr_code}</QrCode>
# </SignedInvoice>"""

#     # Save the signed XML to a file
#     with open('signed_invoice.xml', 'w') as f:
#         f.write(signed_xml_content)

#     return {
#         'signed_invoice_string': signed_xml_content,
#         'invoice_hash': invoice_hash,
#         'qr': qr_code
#     }

# file_path = 'finalzatcaxml.xml'
# cert_path = 'certificatejavaa2.pem'
# key_path = 'new_private.pem'

# try:
#     signed_data = generate_signed_xml_string(file_path, cert_path, key_path)
#     print(signed_data)
# except Exception as e:
#     print("Failed to process:", e)












