import frappe
import xml.etree.ElementTree as ET
from lxml import etree
import hashlib
import base64


# frappe.init(site="prod.erpgulf.com")
# frappe.connect()

def sign_invoice_no_sdk(invoice):
            # settings=frappe.get_doc('Zatca setting')
            # xmlfile_name = 'finalzatcaxml.xml'
            invoice = canonicalize_xml(invoice)
            # signed_xmlfile_name = 'sdsign.xml'
            return invoice
            
def canonicalize_xml (invoice_xml):
            
            namespaces = {
            "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
            "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
            "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
            }
            for elem in invoice_xml.xpath("//ext:UBLExtensions", namespaces=namespaces):
                elem.getparent().remove(elem)
            for elem in invoice_xml.xpath("//cac:Signature", namespaces=namespaces):
                elem.getparent().remove(elem)
            for elem in invoice_xml.xpath("//cac:AdditionalDocumentReference[cbc:ID='QR']", namespaces=namespaces):
                elem.getparent().remove(elem)
   
            invoice_xml_str = etree.tostring(invoice_xml, encoding='unicode', pretty_print=True)
            invoice_xml_dom = etree.fromstring(invoice_xml_str)
            
            parser = etree.XMLParser(remove_blank_text=True)
            xml_tree = etree.fromstring(invoice_xml_str, parser)
            canonicalized_xml_str = etree.tostring(xml_tree, method='c14n').decode()

            return canonicalized_xml_str


def getInvoiceHash(canonicalize_xml):
    
            # // A dumb workaround for whatever reason ZATCA XML devs decided to include those trailing spaces and a newlines. (without it the hash is incorrect)
            canonicalize_xml = canonicalize_xml.replace("<cbc:ProfileID>", "\n    <cbc:ProfileID>");
            canonicalize_xml = canonicalize_xml.replace("<cac:AccountingSupplierParty>", "\n    \n    <cac:AccountingSupplierParty>");
            hash_object = hashlib.sha256(canonicalize_xml.encode())
            base64_encoded = base64.b64encode(hash_object.digest())
            return base64_encoded.decode()



with open("finalzatcaxml.xml", 'r') as file:
        file_content = file.read()
print(type(file_content))
sanitized_invoice = sign_invoice_no_sdk(etree.fromstring(file_content))
# print(type(sanitized_invoice))
print(getInvoiceHash(sanitized_invoice))





