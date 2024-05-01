# from lxml import etree
# import hashlib
# import base64 
# import lxml.etree as MyTree
# from datetime import datetime
# import xml.etree.ElementTree as ET
# import qrcode
# import re 
# import binascii
# from cryptography import x509
# from cryptography.hazmat._oid import NameOID
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.bindings._rust import ObjectIdentifier
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import ec
# from zatca2024.zatca2024.createxml import xml_tags,salesinvoice_data,invoice_Typecode_Simplified,invoice_Typecode_Standard,doc_Reference,additional_Reference ,company_Data,customer_Data,delivery_And_PaymentMeans,tax_Data,item_data,xml_structuring,invoice_Typecode_Compliance,delivery_And_PaymentMeans_for_Compliance,doc_Reference_compliance,get_tax_total_from_items
# import json
# import requests
# from cryptography.hazmat.primitives import serialization

# def get_csr_data():
#     # Read the properties file
#             with open('sdkcsrconfig.properties', 'r') as file:
#                 lines = [line.strip() for line in file.readlines()]

#             # Initialize variables
#             csr_common_name = None
#             csr_serial_number = None
#             csr_organization_identifier = None
#             csr_organization_unit_name = None
#             csr_organization_name = None
#             csr_country_name = None
#             csr_invoice_type = None
#             csr_location_address = None
#             csr_industry_business_category = None

#             # Process each line to extract key-value pairs
#             for line in lines:
#                 parts = line.split('=')
#                 if len(parts) == 2:
#                     key, value = parts
#                     if key == 'csr.common.name':
#                         csr_common_name = value
#                     elif key == 'csr.serial.number':
#                         csr_serial_number = value
#                     elif key == 'csr.organization.identifier':
#                         csr_organization_identifier = value
#                     elif key == 'csr.organization.unit.name':
#                         csr_organization_unit_name = value
#                     elif key == 'csr.organization.name':
#                         csr_organization_name = value
#                     elif key == 'csr.country.name':
#                         csr_country_name = value
#                     elif key == 'csr.invoice.type':
#                         csr_invoice_type = value
#                     elif key == 'csr.location.address':
#                         csr_location_address = value
#                     elif key == 'csr.industry.business.category':
#                         csr_industry_business_category = value

#             return csr_common_name,csr_serial_number,csr_organization_identifier,csr_organization_unit_name,csr_organization_name,csr_country_name,csr_invoice_type,csr_location_address,csr_industry_business_category


# def create_private_keys():
#     private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
#     private_key_pem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     # print(private_key_pem)
#     return private_key_pem

# # private_key_pem = create_private_keys()

# def create_csr(portal_type):
    
#         csr_common_name,csr_serial_number,csr_organization_identifier,csr_organization_unit_name,csr_organization_name,csr_country_name,csr_invoice_type,csr_location_address,csr_industry_business_category = get_csr_data()
#         if portal_type == "sandbox":
#             customoid = b"..TESTZATCA-Code-Signing"
#         elif portal_type == "simulation":
#             customoid = b"..PREZATCA-Code-Signing"
#         else:
#             customoid = b"..ZATCA-Code-Signing"

#         private_key_pem,public_key_pem = create_private_keys()
#         private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        
#         custom_oid_string = "2.5.9.3.7.1.982.20.2"
#         custom_value = customoid
#         oid = ObjectIdentifier(custom_oid_string)
#         custom_extension = x509.extensions.UnrecognizedExtension(oid, custom_value)
        
#         dn = x509.Name([
#             x509.NameAttribute(NameOID.COMMON_NAME, csr_common_name),  # csr.common.name
#             x509.NameAttribute(NameOID.COUNTRY_NAME, csr_country_name),   # csr.country.name -  has to be two digits 
#             x509.NameAttribute(NameOID.ORGANIZATION_NAME, csr_organization_name),   # csr.organization.name
#             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, csr_organization_unit_name), # csr.organization.unit.name
#         ])
#         alt_name = x509.SubjectAlternativeName({
#             x509.DirectoryName(x509.Name([
#                 x509.NameAttribute(NameOID.SURNAME, csr_serial_number),   # csr.serial.number-- has to be this format 
#                 x509.NameAttribute(NameOID.USER_ID, csr_organization_identifier),   # csr.organization.identifier - has to be 13 digit with starting and ending digit 3  
#                 x509.NameAttribute(NameOID.TITLE, csr_invoice_type),  # csr.invoice.type - has to be 1100
#                 x509.NameAttribute(NameOID.BUSINESS_CATEGORY, csr_industry_business_category + "/registeredAddress=" + csr_location_address),   # csr.location.address
#             ])),
#         })

#         csr = (
#             x509.CertificateSigningRequestBuilder()
#             .subject_name(dn)
#             .add_extension(custom_extension, critical=False)
#             .add_extension(alt_name, critical=False)
#             .sign(private_key, hashes.SHA256(), backend=default_backend())
#         )
#         mycsr = csr.public_bytes(serialization.Encoding.PEM)
#         base64csr = base64.b64encode(mycsr)
#         encoded_string = base64csr.decode('utf-8')
#         return encoded_string

# # csr_string = create_csr("sandbox")
# # # get_csr_data()
# # # print(privatekey)
# # with open('new_csr.csr', 'w') as file:
# #     file.write(csr_string)
# # with open('new_private.pem', 'w') as file:
# #     file.write(private_key_pem.decode('utf-8'))
# # # print(csr_string)
# # # with open('new_public.pem', 'w') as file:
# # #     file.write(public_key_pem.decode('utf-8'))
# # with open('new_public.pem', 'wb') as f:
# #       f.write(public_key_pem)

# def create_csid():
#     url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
#     payload = json.dumps({
#     "csr": csr_string
#     })
#     headers = {
#     'accept': 'application/json',
#     'OTP': '123345',
#     'Accept-Version': 'V2',
#     'Content-Type': 'application/json',
#     'Cookie': 'TS0106293e=0132a679c07400f36242c054cc5c73a634f51486563baa5cc4d51293c0b38f68d10c82161b3074b1b2dfbe83a1ae5b78f2fd256699'
#     }
#     response = requests.request("POST", url, headers=headers, data=payload)
#     # print(response.text)
#     data=json.loads(response.text)
#                     # compliance_cert =get_auth_headers(data["binarySecurityToken"],data["secret"])
#     concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
#     encoded_value = base64.b64encode(concatenated_value.encode()).decode()

#     with open(f"certficatejavaaa.pem", 'w') as file:   
#         file.write(base64.b64decode(data["binarySecurityToken"]).decode())
# # create_csid()

# def create_public_key():
#      with open("certficatejavaaa.pem", 'r') as file:
#                 base_64= file.read()
#                 cert_base64 = """
#                 -----BEGIN CERTIFICATE-----
#                 {base_64}
#                 -----END CERTIFICATE-----
#                 """.format(base_64=base_64)
#                 print(cert_base64)
#                 cert = x509.load_pem_x509_certificate(cert_base64.encode(), default_backend())
#                 public_key = cert.public_key()
#                 public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
#                 print("Public Key ",public_key_pem)  #  - This is the public-key used in QR code. remove begin and end string
#                 print("            ")
#                 with open('new_public.pem', 'wb') as f:
#                      f.write(public_key_pem)


# # create_public_key()
# def removeTags(finalzatcaxml):
#         #Code corrected by Farook K - ERPGulf
#         xml_file = MyTree.fromstring(finalzatcaxml)
#         xsl_file = MyTree.fromstring('''<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
#                         xmlns:xs="http://www.w3.org/2001/XMLSchema"
#                         xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
#                         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
#                         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
#                         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
#                         exclude-result-prefixes="xs"
#                         version="2.0">
#                         <xsl:output omit-xml-declaration="yes" encoding="utf-8" indent="no"/>
#                         <xsl:template match="node() | @*">
#                             <xsl:copy>
#                                 <xsl:apply-templates select="node() | @*"/>
#                             </xsl:copy>
#                         </xsl:template>
#                         <xsl:template match="//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"></xsl:template>
#                         <xsl:template match="//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"></xsl:template>
#                             <xsl:template match="//*[local-name()='Invoice']/*[local-name()='Signature']"></xsl:template>
#                         </xsl:stylesheet>''')
#         transform = MyTree.XSLT(xsl_file.getroottree())
#         transformed_xml = transform(xml_file.getroottree())
#         # print(transformed_xml)
#         return transformed_xml
        

# def canonicalize_xml (tag_removed_xml):
#             #Code corrected by Farook K - ERPGulf
#             canonical_xml = etree.tostring(tag_removed_xml, method="c14n").decode()
#             # print(canonical_xml)
#             return canonical_xml        

# def getInvoiceHash(canonicalized_xml):
#             #Code corrected by Farook K - ERPGulf
#             hash_object = hashlib.sha256(canonicalized_xml.encode())
#             hash_hex = hash_object.hexdigest()
#             # print(hash_hex)
#             hash_base64 = base64.b64encode(bytes.fromhex(hash_hex)).decode('utf-8')
#             # base64_encoded = base64.b64encode(hash_hex.encode()).decode()
#             return hash_hex,hash_base64
    
    
    
# def digital_signature():
#         with open("new_private.pem", "rb") as key_file:
#                 hash_bytes = bytes.fromhex(hash)
#                 private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
#                 signature = private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
#                 # print(signature)
#                 encoded_signature = base64.b64encode(signature).decode()
#                 # print(encoded_signature)
#                 return encoded_signature

# # digital_signature()

# def extract_certificate_details():
#             with open("certficatejavaaa.pem", 'r') as file:
#                 certificate_content = file.read()
#                 cert_path = 'certificatejavaa2.pem'
#                 with open(cert_path, "w") as file:
#                     file.write("-----BEGIN CERTIFICATE-----\n")
#                     file.write("\n".join(certificate_content[i:i+64] for i in range(0, len(certificate_content), 64)))
#                     file.write("\n-----END CERTIFICATE-----\n")
#                 with open("certificatejavaa2.pem", 'rb') as cert_file:
#                     pem_data = cert_file.read()
#                 cert = x509.load_pem_x509_certificate(pem_data, default_backend())
#                 issuer_name = cert.issuer.rfc4514_string()
#                 serial_number = cert.serial_number
#                 return issuer_name, serial_number


# def certificate_hash():
#                 with open('certficatejavaaa.pem', 'rb') as f:
#                     certificate_data = f.read().decode('utf-8')
#                     # print(certificate_data)
#                 certificate_data_bytes = certificate_data.encode('utf-8')
#                 sha256_hash = hashlib.sha256(certificate_data_bytes).hexdigest()
#                 # print(sha256_hash)
#                 base64_encoded_hash = base64.b64encode(sha256_hash.encode('utf-8')).decode('utf-8')
#                 # print(base64_encoded_hash)
#                 return base64_encoded_hash


# def signxml_modify():
#             encoded_certificate_hash= certificate_hash()
#             issuer_name, serial_number = extract_certificate_details()
#             original_invoice_xml = etree.parse('finalzatcaxml.xml')
#             root = original_invoice_xml.getroot()
#             namespaces = {
#             'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#             'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#             'sac':"urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2", 
#             'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#             'ds': 'http://www.w3.org/2000/09/xmldsig#'}
#             ubl_extensions_xpath = "//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"
#             qr_xpath = "//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"
#             signature_xpath = "//*[local-name()='Invoice']//*[local-name()='Signature']"
#             xpath_dv = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
#             xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
#             xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
#             xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties//xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")
#             element_dv = root.find(xpath_dv, namespaces)
#             element_st = root.find(xpath_signTime, namespaces)
#             element_in = root.find(xpath_issuerName, namespaces)
#             element_sn = root.find(xpath_serialNum, namespaces)
#             element_dv.text = (encoded_certificate_hash)
#             element_st.text =  datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
#             # print(element_st.text)
#             element_in.text = issuer_name
#             element_sn.text = str(serial_number)
#             # print(element_sn.text)
#             with open("after_step_4.xml", 'wb') as file:
#                 original_invoice_xml.write(file,encoding='utf-8',xml_declaration=True,)
#             return namespaces

# def remove_spaces(text):
#             return "".join(text.split())

# def generate_Signed_Properties_Hash(namespaces):
#                 tree = ET.parse('after_step_4.xml')
#                 root = tree.getroot()
#                 properties = root.find(
#                     "./ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties",
#                     namespaces)
#                 linearized_properties = remove_spaces("".join([remove_spaces(ET.tostring(child, encoding='unicode')) for child in properties]))
#                 # print(linearized_properties)
#                 hashed_properties = hashlib.sha256(linearized_properties.encode()).hexdigest()
#                 # print(hashed_properties)
#                 signed_properties_base64 =  base64.b64encode(hashed_properties.encode('utf-8')).decode('utf-8')
#                 return signed_properties_base64

# def populate_The_UBL_Extensions_Output(encoded_signature):
#             updated_invoice_xml = etree.parse('after_step_4.xml')
#             root3 = updated_invoice_xml.getroot()
#             # encoded_signature = digital_signature()
#             # encoded_certificate_hash = certificate_hash()
#             with open("certficatejavaaa.pem", "r") as file:
#               content = file.read()
#             #   print(content)
#             xpath_signvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue")
#             xpath_x509certi = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
#             xpath_digvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue")
#             xpath_digvalue2 = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue")
#             signValue6 = root3.find(xpath_signvalue , namespaces)
#             x509Certificate6 = root3.find(xpath_x509certi , namespaces)
#             digestvalue6 = root3.find(xpath_digvalue , namespaces)
#             digestvalue6_2 = root3.find(xpath_digvalue2 , namespaces)
#             signValue6.text = (encoded_signature)
#             x509Certificate6.text = content
#             digestvalue6.text = (signed_properties_base64)
#             digestvalue6_2.text =(encoded_hash)
#             with open("final_xml_after_sign.xml", 'wb') as file:
#                 updated_invoice_xml.write(file,encoding='utf-8',xml_declaration=True,)


# def extract_public_key_data():
#     with open("new_public.pem", 'r') as file:
#         lines = file.readlines()
#         key_data = ''.join(lines[1:-1])  
#     key_data = key_data.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')
#     key_data = key_data.replace(' ', '').replace('\n', '')
#     return key_data


# # def get_tlv_for_value(tag_num, tag_value):
# #     tag_buf = bytes([tag_num])
# #     tag_value_len_buf = bytes([len(tag_value)])
# #     tag_value_buf = tag_value.encode('utf-8')
# #     bufs_array = [tag_buf, tag_value_len_buf, tag_value_buf]
# #     return b"".join(bufs_array)
# def get_tlv_for_value(tag_num, tag_value):
#     tag_num_buf = bytes([tag_num])
#     if isinstance(tag_value, str):
#         if len(tag_value) < 256:
#             tag_value_len_buf = bytes([len(tag_value)])
#         else:
#             # If length is greater than 255, use multiple bytes to encode the length
#             tag_value_len_buf = bytes([0xFF, (len(tag_value) >> 8) & 0xFF, len(tag_value) & 0xFF])
#         tag_value = tag_value.encode('utf-8')
#     else:
#         tag_value_len_buf = bytes([len(tag_value)])
#     return tag_num_buf + tag_value_len_buf + tag_value


# def tag8_publickey():
#     base64_encoded = extract_public_key_data()  # Assuming extract_public_key_data() returns the base64 encoded public key
#     byte_data = base64.b64decode(base64_encoded)
#     hex_data = binascii.hexlify(byte_data).decode('utf-8')
#     chunks = [hex_data[i:i + 2] for i in range(0, len(hex_data), 2)]
#     value = ''.join(chunks)

#     # Convert the TLV data back to binary
#     binary_data = bytes.fromhex(value)

#     base64_encoded1 = base64.b64encode(binary_data).decode('utf-8')
#     return binary_data


# # tag8_publickey()
# def tag9_signature_ecdsa():
#                 with open('certificatejavaa2.pem', 'rb') as cert_file:
#                     cert_data = cert_file.read()
#                 cert = x509.load_pem_x509_certificate(cert_data, default_backend())
#                 signature = cert.signature
#                 signature_hex = "".join("{:02x}".format(byte) for byte in signature)
#                 signature_bytes = bytes.fromhex(signature_hex)
#                 signature_base64 = base64.b64encode(signature_bytes).decode()
#                 # print(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
#                 # print(f"Signature Value (Hex): {signature_hex}")
#                 # print(f"Signature Value (Base64): {signature_base64}")
#                 return signature_bytes


# # tag9_signature_ecdsa()


# def generate_tlv_xml():
#     with open("final_xml_after_sign.xml", 'rb') as file:
#         xml_data = file.read()
#     root = etree.fromstring(xml_data)
#     namespaces = {
#         'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
#         'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
#         'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
#         'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#         'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#         'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#         'ds': 'http://www.w3.org/2000/09/xmldsig#'
#     }
#     issue_date_xpath = "/ubl:Invoice/cbc:IssueDate"
#     issue_time_xpath = "/ubl:Invoice/cbc:IssueTime"
#     issue_date_results = root.xpath(issue_date_xpath, namespaces=namespaces)
#     issue_time_results = root.xpath(issue_time_xpath, namespaces=namespaces)
#     issue_date = issue_date_results[0].text.strip() if issue_date_results else 'Missing Data'
#     issue_time = issue_time_results[0].text.strip() if issue_time_results else 'Missing Data'
#     issue_date_time = issue_date + 'T' + issue_time + 'Z'
#     tags_xpaths = [
#         (1, "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName"),
#         (2, "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID"),
#         (3, None),  
#         (4, "/ubl:Invoice/cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount"),
#         (5, "/ubl:Invoice/cac:TaxTotal/cbc:TaxAmount"),
#         (6, "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue"),
#         (7, "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue"),
#         (8, None), 
#         (9, None) ,
#     ]
#     result_dict = {}
#     for tag, xpath in tags_xpaths:
#         if isinstance(xpath, str):  
#             elements = root.xpath(xpath, namespaces=namespaces)
#             if elements:
#                 value = elements[0].text if isinstance(elements[0], etree._Element) else elements[0]
#                 result_dict[tag] = value
#             else:
#                 result_dict[tag] = 'Not found'
#         else:
#             result_dict[tag] = xpath  
    
#     result_dict[3] = issue_date_time
#     result_dict[8] = tag8_publickey()
#     result_dict[9] = tag9_signature_ecdsa()

#     return result_dict


# def update_Qr_toXml():
#                             xml_file_path = "final_xml_after_sign.xml"
#                             xml_tree = etree.parse(xml_file_path)
#                             base64_encoded1 = tag8_publickey()
#                             signature_base64 = tag9_signature_ecdsa()

#                             # Find the <cbc:InvoiceTypeCode> element with the name attribute
#                             invoice_type_element = xml_tree.find('.//cbc:InvoiceTypeCode[@name]', namespaces={'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})

#                             if invoice_type_element is not None:
#                                 # Check the value of the name attribute of the InvoiceTypeCode element
#                                 invoice_type_name = invoice_type_element.get('name')
#                                 qr_code_element = None

#                                 # Find the <cac:AdditionalDocumentReference> element based on the InvoiceTypeCode name attribute
#                                 if invoice_type_name == "0200000":
#                                     qr_code_element = xml_tree.find('.//cac:AdditionalDocumentReference[cbc:ID="QR"]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
#                                     if qr_code_element is not None:
#                                         qr_code_element.text = qrCodeB64
#                                     else:
#                                         print("QR code element not found for InvoiceTypeCode name:", invoice_type_name)
#                                 elif invoice_type_name == "0100000":
#                                     qr_code_element = xml_tree.find('.//cac:AdditionalDocumentReference[cbc:ID="QR"]/cac:Attachment/cbc:EmbeddedDocumentBinaryObject', namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
#                                     if qr_code_element is not None:
#                                         qr_code_element.text = qrCodeB64 + base64_encoded1
#                                     else:
#                                         print("QR code element not found for InvoiceTypeCode name:", invoice_type_name)
#                                 else:
#                                     print("Invalid InvoiceTypeCode name:", invoice_type_name)
#                             else:
#                                 print("InvoiceTypeCode element with name attribute not found")

#                             xml_tree.write(xml_file_path, encoding="UTF-8", xml_declaration=True)



# import frappe
# def xml_base64_Decode(signed_xmlfile_name):
#                     try:
#                         with open(signed_xmlfile_name, "r") as file:
#                                         xml = file.read().lstrip()
#                                         base64_encoded = base64.b64encode(xml.encode("utf-8"))
#                                         base64_decoded = base64_encoded.decode("utf-8")
#                                         # print(base64_decoded)
#                                         return base64_decoded
#                     except Exception as e:
#                         print("Error in xml base64:  " + str(e) )


# # xml_base64_Decode('final_xml_after_sign.xml')

# def compliance_api_call():

#         url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"

#         payload = json.dumps({
#         "invoiceHash": encoded_hash,
#         "uuid": "f5e1c71e-fcc8-11ee-9e64-020017019f27",
#         "invoice": xml_base64_Decode('final_xml_after_sign.xml')
#         })
#         headers = {
#         'accept': 'application/json',
#         'Accept-Language': 'en',
#         'Accept-Version': 'V2',
#         'Authorization': 'Basic VFVsSlEwUkVRME5CWWt0blFYZEpRa0ZuU1VkQldYSXJhbm8wWVUxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWsxNFRVUkJNVTFFV1hwUFJFMTNWMmhqVGsxcVozaE5SRUV3VFdwRmQwMUVRWGRYYWtKTlRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWWk5RazFIUVRGVlJVTjNkMDFWYld3MVdWZFJaMUZ1U21oaWJVNXZUVkpCZDBSbldVUldVVkZMUkVGa1JHSXlOVEJpTTA1MlRWSlJkMFZuV1VSV1VWRkVSRUYwUmxGVVJYbE5lbEV4VG1wak5FOVVRbGROUWtGSFFubHhSMU5OTkRsQlowVkhRbE4xUWtKQlFVdEJNRWxCUWt0NVV6QlJUVFJCVDJkTVRESkNaMU5RTkdsWlRGSXlWa2czU1RkSFJXOVJPR295Y1doUmNrSk9TRU5DUmxSYVdrMDRkVzV0TkZwUFNGSmFjRUpxVVRsRVdGQnRPR1JIV0RNMGNrSTVUVU5KVWtocE1Ia3JhbWRpYTNkbllsbDNSRUZaUkZaU01GUkJVVWd2UWtGSmQwRkVRMEp3VVZsRVZsSXdVa0pKUjJSTlNVZGhjRWxIV0UxSlIxVk5WSE4zVDFGWlJGWlJVVVZFUkVsNFRGWlNWRlpJZDNsTVZsSlVWa2gzZWt4WFZtdE5ha3B0VFZkUk5FeFhWVEpaVkVsMFRWUkZlRTlETURWWmFsVTBURmRSTlZsVWFHMU5WRVpzVGtSUk1WcHFSV1pOUWpCSFEyZHRVMHB2YlZRNGFYaHJRVkZGVFVSNlRYaE5SRVY1VFdwTk5VMTZWWGROUkVGM1RYcEZUazFCYzBkQk1WVkZSRUYzUlUxVVJYZE5SRVZUVFVKQlIwRXhWVVZIWjNkS1ZGaHNRbHBIVW5sYVdFNTZUVkpGZDBSM1dVUldVVkZRUkVGb1NtSnRVakZqTTFKNVpWUkJTMEpuWjNGb2EycFBVRkZSUkVGblRrbEJSRUpHUVdsQ0syRTNiM2xLYldGa2NYRjBSbGgwZVZKMGFHMTNielk1ZWxaNFZtSjVSbHBuVUZwNmMwUlVTamxoWjBsb1FVcDVWV1pJTXpScVlXaDRiR0UxVGtJMmFWbHhTWGxUT1VWME5FRXlWV3d2TVVoM1VXYzNURVZ5UmtRPToyWmhjTmpQV2FUK09LVWVnK0RTcmR3RUg0OXVpalFpaEN6emUyd1lmYktNPQ==',
#         'Content-Type': 'application/json',
#         'Cookie': 'TS0106293e=0132a679c0b10cf6c29a653de982233d1a963a1c3d67ad649e41021b0a7b1825208bb7e7615f60058af4ed60330ae0c3dfb7f76f29'
#         }
#         response = requests.request("POST", url, headers=headers, data=payload)
#         print(response.text)
# # with open("finalzatcaxml.xml", 'r') as file:
# #         file_content = file.read()
        
# # tag_removed_xml = removeTags(file_content)
# # canonicalized_xml = canonicalize_xml(tag_removed_xml)
# # # print(canonicalized_xml)

# # hash, encoded_hash = getInvoiceHash(canonicalized_xml)

# # print(hash)
# # print(encoded_hash)

# # encoded_signature=digital_signature()
# # extract_certificate_details()
# # certificate_hash()
# # namespaces=signxml_modify()
# # signed_properties_base64=generate_Signed_Properties_Hash(namespaces)
# # populate_The_UBL_Extensions_Output(encoded_signature)
# # tlv_data = generate_tlv_xml()
# # tagsBufsArray = []
# # for tag_num, tag_value in tlv_data.items():
# #     tagsBufsArray.append(get_tlv_for_value(tag_num, tag_value))
# # qrCodeBuf = b"".join(tagsBufsArray)
# # # print(qrCodeBuf)
# # qrCodeB64 = base64.b64encode(qrCodeBuf).decode('utf-8')
# # print(qrCodeB64)
# # update_Qr_toXml()
# # compliance_api_call()


# import binascii
# # import pyqrcode

# # def qr_img():
# #         qr_value = qrCodeB64
# #         qr = pyqrcode.create(qr_value)
# #         temp_file_path = "qr_codeextag.png"
# #         qr_image=qr.png(temp_file_path, scale=5)

# # # qr_img()

# # hex_string = "3056301006072A8648CE3D020106052B8104000A03420004A1608A6B449AF45204AD33AFD2E0240B5548297C54F673E9C76BE57F8CA131E8F2F1CD365C96E50EAEED3F2768F26AB46A138C98DA3C8309E2ED7B75293F5478"
# # byte_data = binascii.unhexlify(hex_string)
# # print(byte_data)
# # base64_encoded = base64.b64encode(byte_data).decode('utf-8')
# # print(base64_encoded)
# # hex_data = binascii.hexlify(byte_data).decode('utf-8')
# # print(hex_data)
# def production_CSID():    
#                 try:
#                     payload = json.dumps({
#                     "compliance_request_id":"1234567890123"})
#                     headers = {
#                     'accept': 'application/json',
#                     'Accept-Version': 'V2',
#                     'Authorization': 'Basic'+ "VFVsSlEwaDZRME5CWTFkblFYZEpRa0ZuU1VkQldUaHZUM0UzVDAxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWxGM1RrUkpOVTFFVlhkTlZFbDNWMmhqVGsxcWEzZE9SRWswVFdwRmQwMUVRWGRYYWtKVFRWSnJkMFozV1VSV1VWRkVSRUpCZWsxRVFYaE5WR042VFZSak5VNVVRWGROUkVGNlRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWUk5Ra1ZIUVRGVlJVTm5kMHROZWtGNFRWUmplazFVWXpWT1ZFVlVUVUpGUjBFeFZVVkRkM2RMVFhwQmVFMVVZM3BOVkdNMVRsUkNWMDFDUVVkQ2VYRkhVMDAwT1VGblJVZENVM1ZDUWtGQlMwRXdTVUZDUWtORFExaFVkVFEyZDFsUVQwVkVVamx5VTNFM2QwZFRTRE53WVVsdmJqQk5LMFp5WkdsRGJFWkthRFE0YmpaUGRtRk9ZM0o1TmtwcE1WRmFPRGh4V0Vrd1dEVjRPRzlMUzBkR1NEbERNV3B3ZFN0M05uRnFaMk5aZDJkalRYZEVRVmxFVmxJd1ZFRlJTQzlDUVVsM1FVUkRRbk5uV1VSV1VqQlNRa2xIY1UxSlIyNXdTVWRyVFVsSGFFMVVjM2RQVVZsRVZsRlJSVVJFU1hoTVZsSlVWa2gzZVV4V1VsUldTSGQ2VEZkV2EwMXFTbTFOVjFFMFRGZFZNbGxVU1hSTlZFVjRUME13TlZscVZUUk1WMUUxV1ZSb2JVMVVSbXhhUkZVMFQwUkZaazFDTUVkRFoyMVRTbTl0VkRocGVHdEJVVVZOUkhwTmQwMVVSVE5OZWtVelQxUlZkMDFFUVhkTmVrVk9UVUZ6UjBFeFZVVkVRWGRGVFZSRmQwMUVSWGxOUkVGSFFURlZSVVIzZDNCVk0xWjNZMGM1ZVdSRFFsUmFXRW95WVZkT2JHTjVPWGxhVjJSd1l6TlNiR050Vm10UlYxSnJZMjFXZW1ONk1WTlRWbXhDVWtWbmQwTm5XVWxMYjFwSmVtb3dSVUYzU1VSVFFVRjNVbEZKWjJST2JrSlZaVTVLV0hjdlRHbEZkMmgzYTFjM2VrdHJLMlEwYzFCVU5rTjJia2N2WlhGV2FGSk9NelJEU1ZGRVdFRndkVFF2VTNsMVVqWTJaRzRyVUVKamNUSjVLM0kyTWxSRlVGZExXSGwzYzFCamNFOXlia2sxWnowOTpMZFF5N1dkbHdkVDg1MmR0aUpickxDUzduSGw2ZlkrQy9rbmt4YnZiNUNnPQ==",
#                     # 'Authorization': 'Basic'+ "VkZWc1NsRXhTalpSTUU1Q1dsaHNibEZZWkVwUmEwWnVVMVZrUWxkWWJGcFhhazAxVTJzeFFtSXdaRVJSTTBaSVZUQXdNRTlWU2tKVVZVNU9VV3hXTkZKWWNFSlZhMHB1Vkd4YVExRlZNVTVSTWpGWFUyMUtkVmR1V21oV01EVjNXVzB4YW1Rd2FHOVpNRFZPWVdzeE5GUlhjRXBsYXpGeFVWaHdVRlpGYkRaV01taHFWR3N4Y1ZvemFFNWhhMncxVkZkd1JtUXdNVVZSV0dSWVlXdEpNVlJXUm5wa01FNVNWMVZTVjFWV1JraFNXR1JMVmtaR1ZWSldiRTVSYkd4SVVWUkdWbEpWVGpOa01VSk9aV3RHTTFReFVtcGtNRGxGVVZSS1RsWkZSak5VVlZKQ1pXc3hWRm96WkV0YU1XeEZWbXhHVWxNd1VrTlBWVXBzVWpKNE5sTlZWbk5rVjAxNlVXMTRXazB4U25kWmFra3dXakZGZVU5WVZtdFRSWEJ2VjFST1UyTkhTblJaTW1SVVlrVTFSVlJXVGxwa01IQkNWMVZTVjFWV1JrVlNSVWw0VmxaVmVGVllVbEJTUjJONVZHdFNUbVZGTVZWVlZFWk5Wa1V4TTFSVlVuSk5NREZGV2pOa1QyRnJWak5VVlZKQ1pEQXhObEZzWkU1UmEwWklVVzVzZUZJeFRrNU9SR3hDV2pCV1NGRnNUakZSYTBwQ1VWVjBRazFGYkVKUmEzaFNZVWhDV1UxRlNrVmtSVVpTVDFWS05rOUhaM2ROYms1M1ZrWkdTbFZWVGpKT1YyYzBWRmhHTkdGRVVuQlRSVEYzVVcwNGRsRnRPWEJXUm1ScllsTjBVMWRYV2t0aVZYQlBaR3BrV1dSdVZUVk5NbHAyVjFjME1FNVVhRTlTTVVwdVltNW5NazVIV2xkaGJUbFdUREZDTVdGdFpHcFhXR1J1V1RBeE0xSkZSbHBTUmxwVFRVWlNRbFZWWjNaUmEwWktaREJHUlZFd1NucGFNV3hGVm14SmQxVnJTa3BTTTBaT1UxVmtkV05GYkVoaE1ERktVakpvVGxaSVRqTlVNVVphVWtaYVVsVlZWa1ZTUld3MFZFWmFVMVpHV2tsa00yeE5WbXhLVlZacmFETmxhM2hZVm0xMFRtRnJjSFJVVm1SU1RrVjRXRlpVU2xwV1JXd3dWRlpTUm1WRk9VUk5SRlphWVd4Vk1GUkdaRkpPVm14VllVY3hUbFpGV25OVWExSlNUVlp3Y1ZKWFdrNVJha0pJVVRKa2RGVXdjSFppVmxFMFlWaG9jbEZXUmtaVVZWSTJWRmhrVGxKSGMzcFVWVkp1WkRBMWNWSllaRTVTUlVZelZGaHdSbFJyTVVKak1HUkNUVlpXUmxKRlJqTlNWVEZWVWxob1RsWkZWbE5VVlVVMFVqQkZlRlpWVmtoYU0yUktWbGQ0UzFVeFNrVlRWRlpPWVcxME5GTkljRUphUlVwdVZHeGFRMUZVYUU1U2JYaExZa1pzV0dReVpHRlhSVFIzVjFab1UySkZiRWhTYlhCclVqSjNlVmxXYUZOalJuQlpWRmhrUkZveGJFcFRNamxoVTFod2NVMUZWa0prTUd4RlZURkdRbVF4U201VFYyaENWRmhHVTFOclJYSlZSRTVKVkVac2FWUXdNRFJPVldoTFRETmtUMlZ0UmxkT01XUnFXbTVKZGxkcVRqRmpWR3hMVFRCV1ZHTnNXbHBsYTBad1VsVkdkazV0YUdwUFZGSlRVMGR3YldRelRuZFpVemwzVjBaYWRWWnBPWFpWVjBaT1QxUk9hVTVzU1RKaVYyUmhWMFJDTVZGV1RYbE5WVnB1VUZFOVBRPT06eXRabHl6YklXY0wrUHlETytFd1JqWHRHSEp4SHB3cXdJYUVsaGxMQVJZQT0=",
#                     # 'Authorization': 'Basic'+ "VFVsSlExSjZRME5CWlhsblFYZEpRa0ZuU1VkQldYbFpXak01U2sxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWsxNFRXcEplazFxUVhwUFZFbDZWMmhqVGsxcVozaE5ha2w1VFdwRmQwMUVRWGRYYWtJMVRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWbE5RbGxIUVRGVlJVTjNkMUJOZWtGM1QxUmpkMDlFUVRKTlZFRjNUVVJCZWsxVFozZEtaMWxFVmxGUlMwUkNPVUpsUjJ4NlNVVnNkV016UW14Wk0xSndZakkwWjFFeU9YVmtTRXBvV1ROU2NHSnRZMmRUYkU1RVRWTlpkMHBCV1VSV1VWRkVSRUl4VlZVeFVYUlBSR2N5VGtSTmVFMVVVVEZNVkUxM1RVUnJNMDFFWjNkT2FrVjNUVVJCZDAxNlFsZE5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVV0Qk1FbEJRa3hSYUhCWU1FSkVkRUZST1VKNk9HZ3dNbk53VkZGSlVVTjJOV2c0VFhGNGFEUnBTRTF3UW04dlFtOXBWRmRrYlN0U1dXWktiVXBPZGpkWWRuVTVNMlp2V1c0ME5UaE9SMUpuYm5nMk5HWldhbTlWTDFCMWFtZGpXWGRuWTAxM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVEwSnpaMWxFVmxJd1VrSkpSM0ZOU1VkdWNFbEhhMDFKUjJoTlZITjNUMUZaUkZaUlVVVkVSRWw0VEZaU1ZGWklkM2xNVmxKVVZraDNla3hYVm10TmFrcHRUVmRSTkV4WFZUSlpWRWwwVFZSRmVFOURNRFZaYWxVMFRGZFJOVmxVYUcxTlZFWnNUa1JSTVZwcVJXWk5RakJIUTJkdFUwcHZiVlE0YVhoclFWRkZUVVI2VFhkTlJHc3pUVVJuZDA1cVJYZE5SRUYzVFhwRlRrMUJjMGRCTVZWRlJFRjNSVTFVUlhoTlZFVlNUVUU0UjBFeFZVVkhaM2RKVld4S1UxSkVTVFZOYW10NFNIcEJaRUpuVGxaQ1FUaE5SbXhLYkZsWGQyZGFXRTR3V1ZoU2JFbEhSbXBrUjJ3eVlWaFNjRnBZVFhkRFoxbEpTMjlhU1hwcU1FVkJkMGxFVTFGQmQxSm5TV2hCVFhGU1NrRXJVRE5JVEZsaVQwMDROVWhLTDNkT2VtRldOMWRqWm5JdldqTjFjVGxLTTBWVGNsWlpla0ZwUlVGdk5taGpPVFJTU0dwbWQzTndZUzl3V0ZadVZpOXZVV0ZOT1ROaU5sSTJiV2RhV0RCMVFWTXlNVVpuUFE9PTp5dFpseXpiSVdjTCtQeURPK0V3UmpYdEdISnhIcHdxd0lhRWxobExBUllBPQ==",
#                     'Content-Type': 'application/json' }
#                     response = requests.request("POST", url="https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/production/csids", headers=headers, data=payload)
#                     # print(response.text)
#                     if response.status_code != 200:
#                         print("Error: " + str(response.text))
#                     data=json.loads(response.text)
#                     concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
#                     encoded_value = base64.b64encode(concatenated_value.encode()).decode()
#                     with open(f"certficatejavaaa.pem", 'w') as file:   #attaching X509 certificate
#                         file.write(base64.b64decode(data["binarySecurityToken"]).decode('utf-8'))
                    
#                 except Exception as e:
#                     print("error in  production csid formation:  " + str(e) )


# # production_CSID()




# def clearance_API():
#                     try:
#                         print("ji")
#                         payload = json.dumps({
#                         "invoiceHash": encoded_hash,
#                         "uuid": "f5e1c71e-fcc8-11ee-9e64-020017019f27",
#                         "invoice": xml_base64_Decode('final_xml_after_sign.xml'), })
#                         # print(payload)
#                         headers = {
#                         'accept': 'application/json',
#                         'accept-language': 'en',
#                         'Clearance-Status': '1',
#                         'Accept-Version': 'V2',
#                         'Authorization': 'Basic' + "VFVsSlEwaDZRME5CWTFkblFYZEpRa0ZuU1VkQldUaHZUM0UzVDAxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWxGM1RrUkpOVTFFVlhkTlZFbDNWMmhqVGsxcWEzZE9SRWswVFdwRmQwMUVRWGRYYWtKVFRWSnJkMFozV1VSV1VWRkVSRUpCZWsxRVFYaE5WR042VFZSak5VNVVRWGROUkVGNlRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWUk5Ra1ZIUVRGVlJVTm5kMHROZWtGNFRWUmplazFVWXpWT1ZFVlVUVUpGUjBFeFZVVkRkM2RMVFhwQmVFMVVZM3BOVkdNMVRsUkNWMDFDUVVkQ2VYRkhVMDAwT1VGblJVZENVM1ZDUWtGQlMwRXdTVUZDUWtORFExaFVkVFEyZDFsUVQwVkVVamx5VTNFM2QwZFRTRE53WVVsdmJqQk5LMFp5WkdsRGJFWkthRFE0YmpaUGRtRk9ZM0o1TmtwcE1WRmFPRGh4V0Vrd1dEVjRPRzlMUzBkR1NEbERNV3B3ZFN0M05uRnFaMk5aZDJkalRYZEVRVmxFVmxJd1ZFRlJTQzlDUVVsM1FVUkRRbk5uV1VSV1VqQlNRa2xIY1UxSlIyNXdTVWRyVFVsSGFFMVVjM2RQVVZsRVZsRlJSVVJFU1hoTVZsSlVWa2gzZVV4V1VsUldTSGQ2VEZkV2EwMXFTbTFOVjFFMFRGZFZNbGxVU1hSTlZFVjRUME13TlZscVZUUk1WMUUxV1ZSb2JVMVVSbXhhUkZVMFQwUkZaazFDTUVkRFoyMVRTbTl0VkRocGVHdEJVVVZOUkhwTmQwMVVSVE5OZWtVelQxUlZkMDFFUVhkTmVrVk9UVUZ6UjBFeFZVVkVRWGRGVFZSRmQwMUVSWGxOUkVGSFFURlZSVVIzZDNCVk0xWjNZMGM1ZVdSRFFsUmFXRW95WVZkT2JHTjVPWGxhVjJSd1l6TlNiR050Vm10UlYxSnJZMjFXZW1ONk1WTlRWbXhDVWtWbmQwTm5XVWxMYjFwSmVtb3dSVUYzU1VSVFFVRjNVbEZKWjJST2JrSlZaVTVLV0hjdlRHbEZkMmgzYTFjM2VrdHJLMlEwYzFCVU5rTjJia2N2WlhGV2FGSk9NelJEU1ZGRVdFRndkVFF2VTNsMVVqWTJaRzRyVUVKamNUSjVLM0kyTWxSRlVGZExXSGwzYzFCamNFOXlia2sxWnowOTpMZFF5N1dkbHdkVDg1MmR0aUpickxDUzduSGw2ZlkrQy9rbmt4YnZiNUNnPQ==",
#                         # 'Authorization': 'Basic' + settings.basic_auth,
                        
#                         'Content-Type': 'application/json',
#                         'Cookie': 'TS0106293e=0132a679c03c628e6c49de86c0f6bb76390abb4416868d6368d6d7c05da619c8326266f5bc262b7c0c65a6863cd3b19081d64eee99' }
                        
#                         response = requests.request("POST", url="https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/invoices/clearance/single", headers=headers, data=payload)
#                         print(response.text)
#                         print(response)
                            
#                     except Exception as e:
#                         print("error in clearance api:  " + str(e) )
# # clearance_API()



