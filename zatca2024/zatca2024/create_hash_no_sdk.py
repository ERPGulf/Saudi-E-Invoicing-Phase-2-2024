from lxml import etree
import hashlib
import base64 
import lxml.etree as MyTree
from datetime import datetime
import xml.etree.ElementTree as ET
import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509

def removeTags(finalzatcaxml):
        #Code corrected by Farook K - ERPGulf
        xml_file = MyTree.fromstring(finalzatcaxml)
        xsl_file = MyTree.fromstring('''<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                        xmlns:xs="http://www.w3.org/2001/XMLSchema"
                        xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
                        xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
                        xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
                        xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
                        exclude-result-prefixes="xs"
                        version="2.0">
                        <xsl:output omit-xml-declaration="yes" encoding="utf-8" indent="no"/>
                        <xsl:template match="node() | @*">
                            <xsl:copy>
                                <xsl:apply-templates select="node() | @*"/>
                            </xsl:copy>
                        </xsl:template>
                        <xsl:template match="//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"></xsl:template>
                        <xsl:template match="//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"></xsl:template>
                            <xsl:template match="//*[local-name()='Invoice']/*[local-name()='Signature']"></xsl:template>
                        </xsl:stylesheet>''')
        transform = MyTree.XSLT(xsl_file.getroottree())
        transformed_xml = transform(xml_file.getroottree())
        # print(transformed_xml)
        return transformed_xml
        

def canonicalize_xml (tag_removed_xml):
            #Code corrected by Farook K - ERPGulf
            canonical_xml = etree.tostring(tag_removed_xml, method="c14n").decode()
            # print(canonical_xml)
            return canonical_xml        

def getInvoiceHash(canonicalized_xml):
            #Code corrected by Farook K - ERPGulf
            hash_object = hashlib.sha256(canonicalized_xml.encode())
            hash_hex = hash_object.hexdigest()
            # print(hash_hex)
            hash_base64 = base64.b64encode(bytes.fromhex(hash_hex)).decode('utf-8')
            # base64_encoded = base64.b64encode(hash_hex.encode()).decode()
            return hash_hex,hash_base64
    
    
    
with open("finalzatcaxml.xml", 'r') as file:
        file_content = file.read()
        
tag_removed_xml = removeTags(file_content)
canonicalized_xml = canonicalize_xml(tag_removed_xml)
# print(canonicalized_xml)

hash, encoded_hash = getInvoiceHash(canonicalized_xml)

# print(hash)
# print(encoded_hash)



def digital_signature():
        with open("new_private.pem", "rb") as key_file:
                hash_bytes = bytes.fromhex(hash)
                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                signature = private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
                print(signature)
                encoded_signature = base64.b64encode(signature).decode()
                print(encoded_signature)
                return encoded_signature
# digital_signature()




def extract_certificate_details():
            with open("certficatejavaaa.pem", 'r') as file:
                certificate_content = file.read()
                cert_path = 'certificatejavaa2.pem'
                with open(cert_path, "w") as file:
                    file.write("-----BEGIN CERTIFICATE-----\n")
                    file.write("\n".join(certificate_content[i:i+64] for i in range(0, len(certificate_content), 64)))
                    file.write("\n-----END CERTIFICATE-----\n")
                with open("certificatejavaa2.pem", 'rb') as cert_file:
                    pem_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                issuer_name = cert.issuer.rfc4514_string()
                serial_number = cert.serial_number
                return issuer_name, serial_number




def certificate_hash():
        with open("certficatejavaaa.pem", "r") as file:
            content = file.read()
            certificate_hash_object = hashlib.sha256(content.encode())
            certificate_hash_hex = certificate_hash_object.digest()  # Use .digest() to get binary hash
            encoded_certificate_hash = base64.b64encode(certificate_hash_hex).decode('utf-8')
            # print(encoded_certificate_hash)
            return encoded_certificate_hash



def signxml_modify():
            encoded_certificate_hash= certificate_hash()
            issuer_name, serial_number = extract_certificate_details()
            original_invoice_xml = etree.parse('finalzatcaxml.xml')
            root = original_invoice_xml.getroot()
            namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac':"urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2", 
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'}
            ubl_extensions_xpath = "//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"
            qr_xpath = "//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"
            signature_xpath = "//*[local-name()='Invoice']//*[local-name()='Signature']"
            xpath_dv = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
            xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
            xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
            xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties//xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")
            element_dv = root.find(xpath_dv, namespaces)
            element_st = root.find(xpath_signTime, namespaces)
            element_in = root.find(xpath_issuerName, namespaces)
            element_sn = root.find(xpath_serialNum, namespaces)
            element_dv.text = (encoded_certificate_hash)
            element_st.text = str(datetime.utcnow().isoformat())
            # print(element_st.text)
            element_in.text = issuer_name
            element_sn.text = str(serial_number)
            # print(element_sn.text)
            with open("after_step_4.xml", 'wb') as file:
                original_invoice_xml.write(file,encoding='utf-8',xml_declaration=True,)
            return original_invoice_xml,namespaces

def generate_Signed_Properties_Hash(original_invoice_xml,namespaces):
            xml_from_step_4 = etree.parse('after_step_4.xml')
            root2 = original_invoice_xml.getroot()
            xpath_signedProp = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties")
            signed_prop_tag = root2.find(xpath_signedProp , namespaces)
            signed_properties_xml = ET.tostring(signed_prop_tag , encoding='utf-8').decode().replace(" ", "")
            signed_properties_hash = hashlib.sha256(signed_properties_xml.encode()).digest()
            signed_properties_hex = signed_properties_hash.hex()
            signed_properties_base64 = base64.b64encode(bytes.fromhex(signed_properties_hex)).decode()
            # print(signed_properties_base64)
            return signed_properties_base64

original_invoice_xml,namespaces=signxml_modify()
signed_properties_base64=generate_Signed_Properties_Hash(original_invoice_xml,namespaces)


def populate_The_UBL_Extensions_Output():
            updated_invoice_xml = etree.parse('after_step_4.xml')
            root3 = updated_invoice_xml.getroot()
            encoded_signature = digital_signature()
            encoded_certificate_hash = certificate_hash()
            with open("certficatejavaaa.pem", "r") as file:
              content = file.read()
            #   print(content)
            xpath_signvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue")
            xpath_x509certi = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
            xpath_digvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue")
            xpath_digvalue2 = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue")
            signValue6 = root3.find(xpath_signvalue , namespaces)
            x509Certificate6 = root3.find(xpath_x509certi , namespaces)
            digestvalue6 = root3.find(xpath_digvalue , namespaces)
            digestvalue6_2 = root3.find(xpath_digvalue2 , namespaces)
            signValue6.text = (encoded_signature)
            x509Certificate6.text = content
            digestvalue6.text = (signed_properties_base64)
            digestvalue6_2.text =(encoded_hash)
            with open("final_xml_after_sign.xml", 'wb') as file:
                updated_invoice_xml.write(file,encoding='utf-8',xml_declaration=True,)
            




import base64
from lxml import etree

def generate_tlv_xml(xml_path):
    # Load the XML file
    with open(xml_path, 'rb') as file:
        xml_data = file.read()

    # Parse the XML
    xml_root = etree.XML(xml_data)

    # Define namespaces for the XML
    namespaces = {
        'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
        'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
        'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
        'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
        'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
        'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
        'ds': 'http://www.w3.org/2000/09/xmldsig#'
    }

    # XPath expressions for the required fields
    paths = {
        'sellerName': "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName",
        'vatNumber': "/ubl:Invoice/cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID",
        'timeStamp': "concat(/ubl:Invoice/cbc:IssueDate, 'T', /ubl:Invoice/cbc:IssueTime, 'Z')",
        'invoiceTotal': "/ubl:Invoice/cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount",
        'vatTotal': "/ubl:Invoice/cac:TaxTotal/cbc:TaxAmount",
        'signatureValue': "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue",
        'ecdsaPublicKey': "/ubl:Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
    }

    # Prepare data for TLV encoding
    tlv_data = bytearray()
    tag = 1

    for key, xpath in paths.items():
        results = xml_root.xpath(xpath, namespaces=namespaces)
        value = results[0].text if results else 'Missing Data'
        tlv_data.extend(bytes([tag]))  # Tag
        tlv_data.extend(len(value.encode()).to_bytes(2, 'big'))  # Length
        tlv_data.extend(value.encode())  # Value
        tag += 1

    # Handle sbDigestValue, assumed to be predefined or obtained elsewhere
    # For this example, we'll create a placeholder for the encoded_hash
     # Placeholder value
    sbDigestValue = encoded_hash
    tlv_data.extend(bytes([tag]))  # Tag
    tlv_data.extend(len(sbDigestValue.encode()).to_bytes(2, 'big'))  # Length
    tlv_data.extend(sbDigestValue.encode())  # Value

    # Encode the whole data to Base64
    tlv_encoded = base64.b64encode(tlv_data).decode('utf-8')
    print("TLV encoded QR data is:", tlv_encoded)

    return tlv_encoded

# Example usage of the function

tlv_encoded_data = generate_tlv_xml('final_xml_after_sign.xml')