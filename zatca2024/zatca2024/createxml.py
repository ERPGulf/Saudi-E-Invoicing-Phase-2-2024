#utilites for zatca2024

import frappe
import os
# frappe.init(site="prod.erpgulf.com")
# frappe.connect()
import xml.etree.ElementTree as ET
from lxml import etree
import xml.dom.minidom as minidom
import uuid 
from frappe.utils import now
import re
from lxml import etree
from frappe.utils.data import  get_time
import xml.etree.ElementTree as ET
import json
import xml.etree.ElementTree as ElementTree

def get_Tax_for_Item(full_string,item):
            try:                                          # getting tax percentage and tax amount
                data = json.loads(full_string)
                tax_percentage=data.get(item,[0,0])[0]
                tax_amount = data.get(item, [0, 0])[1]
                return tax_amount,tax_percentage
            except Exception as e:
                    frappe.throw("error occured in tax for item"+ str(e) )

def get_ICV_code(invoice_number):
                try:
                    icv_code =  re.sub(r'\D', '', invoice_number)   # taking the number part only from doc name
                    return icv_code
                except Exception as e:
                    frappe.throw("error in getting icv number:  "+ str(e) )
                    
def  get_Issue_Time(invoice_number): 
                doc = frappe.get_doc("Sales Invoice", invoice_number)
                time = get_time(doc.posting_time)
                issue_time = time.strftime("%H:%M:%S")  #time in format of  hour,mints,secnds
                return issue_time
  
def xml_tags():
            try: 
                invoice = ET.Element("Invoice", xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" )
                invoice.set("xmlns:cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2")
                invoice.set("xmlns:cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2")
                invoice.set("xmlns:ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2")   
                ubl_extensions = ET.SubElement(invoice, "ext:UBLExtensions")
                ubl_extension = ET.SubElement(ubl_extensions, "ext:UBLExtension")
                extension_uri = ET.SubElement(ubl_extension, "ext:ExtensionURI")
                extension_uri.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
                extension_content = ET.SubElement(ubl_extension, "ext:ExtensionContent")
                UBL_Document_Signatures = ET.SubElement(extension_content , "sig:UBLDocumentSignatures"    )
                UBL_Document_Signatures.set("xmlns:sig" , "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2")
                UBL_Document_Signatures.set("xmlns:sac" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2")
                UBL_Document_Signatures.set("xmlns:sbc" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2")
                Signature_Information = ET.SubElement(UBL_Document_Signatures , "sac:SignatureInformation"  )
                id = ET.SubElement(Signature_Information , "cbc:ID"  )
                id.text = "urn:oasis:names:specification:ubl:signature:1"
                Referenced_SignatureID = ET.SubElement(Signature_Information , "sbc:ReferencedSignatureID"  )
                Referenced_SignatureID.text = "urn:oasis:names:specification:ubl:signature:Invoice"
                Signature = ET.SubElement(Signature_Information , "ds:Signature"  )
                Signature.set("Id" , "signature" )
                Signature.set("xmlns:ds" , "http://www.w3.org/2000/09/xmldsig#" )
                Signed_Info = ET.SubElement(Signature , "ds:SignedInfo"  )
                Canonicalization_Method = ET.SubElement(Signed_Info , "ds:CanonicalizationMethod"  )
                Canonicalization_Method.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11"  )
                Signature_Method = ET.SubElement(Signed_Info , "ds:SignatureMethod"  )
                Signature_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"  )
                Reference = ET.SubElement(Signed_Info , "ds:Reference"  )
                Reference.set("Id"  , "invoiceSignedData")
                Reference.set("URI"  , "")
                Transforms = ET.SubElement(Reference , "ds:Transforms" )
                Transform = ET.SubElement(Transforms , "ds:Transform" )
                Transform.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath = ET.SubElement(Transform , "ds:XPath" )
                XPath.text = "not(//ancestor-or-self::ext:UBLExtensions)"
                Transform2 = ET.SubElement(Transforms , "ds:Transform" )
                Transform2.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath2 = ET.SubElement(Transform2 , "ds:XPath" )
                XPath2.text = "not(//ancestor-or-self::cac:Signature)"
                Transform3 = ET.SubElement(Transforms , "ds:Transform" )
                Transform3.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath3 = ET.SubElement(Transform3 , "ds:XPath" )
                XPath3.text = "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])"
                Transform4 = ET.SubElement(Transforms , "ds:Transform" )
                Transform4.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11")
                Diges_Method = ET.SubElement(Reference , "ds:DigestMethod" )
                Diges_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Diges_value = ET.SubElement(Reference , "ds:DigestValue" )
                Diges_value.text = "O/vEnAxjLAlw8kQUy8nq/5n8IEZ0YeIyBFvdQA8+iFM="
                Reference2 = ET.SubElement(Signed_Info , "ds:Reference"  )
                Reference2.set("URI" , "#xadesSignedProperties")
                Reference2.set("Type" , "http://www.w3.org/2000/09/xmldsig#SignatureProperties")
                Digest_Method1 = ET.SubElement(Reference2 , "ds:DigestMethod"  )
                Digest_Method1.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Digest_value1 = ET.SubElement(Reference2 , "ds:DigestValue"  )
                Digest_value1.text="YjQwZmEyMjM2NDU1YjQwNjM5MTFmYmVkODc4NjM2NTc0N2E3OGFmZjVlMzA1ODAwYWE5Y2ZmYmFjZjRiNjQxNg=="
                Signature_Value = ET.SubElement(Signature , "ds:SignatureValue"  )
                Signature_Value.text = "MEQCIDGBRHiPo6yhXIQ9df6pMEkufcGnoqYaS+O8Jn0xagBiAiBtoxpbrwfEJHhUGQHTqzD1ORX5+Z/tumM0wLfZ4cuYRg=="
                KeyInfo = ET.SubElement(Signature , "ds:KeyInfo"  )
                X509Data = ET.SubElement(KeyInfo , "ds:X509Data"  )
                X509Certificate = ET.SubElement(X509Data , "ds:X509Certificate"  )
                X509Certificate.text = "MIID6TCCA5CgAwIBAgITbwAAf8tem6jngr16DwABAAB/yzAKBggqhkjOPQQDAjBjMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNnb3YxFzAVBgoJkiaJk/IsZAEZFgdleHRnYXp0MRwwGgYDVQQDExNUU1pFSU5WT0lDRS1TdWJDQS0xMB4XDTIyMDkxNDEzMjYwNFoXDTI0MDkxMzEzMjYwNFowTjELMAkGA1UEBhMCU0ExEzARBgNVBAoTCjMxMTExMTExMTExDDAKBgNVBAsTA1RTVDEcMBoGA1UEAxMTVFNULTMxMTExMTExMTEwMTExMzBWMBAGByqGSM49AgEGBSuBBAAKA0IABGGDDKDmhWAITDv7LXqLX2cmr6+qddUkpcLCvWs5rC2O29W/hS4ajAK4Qdnahym6MaijX75Cg3j4aao7ouYXJ9GjggI5MIICNTCBmgYDVR0RBIGSMIGPpIGMMIGJMTswOQYDVQQEDDIxLVRTVHwyLVRTVHwzLWE4NjZiMTQyLWFjOWMtNDI0MS1iZjhlLTdmNzg3YTI2MmNlMjEfMB0GCgmSJomT8ixkAQEMDzMxMTExMTExMTEwMTExMzENMAsGA1UEDAwEMTEwMDEMMAoGA1UEGgwDVFNUMQwwCgYDVQQPDANUU1QwHQYDVR0OBBYEFDuWYlOzWpFN3no1WtyNktQdrA8JMB8GA1UdIwQYMBaAFHZgjPsGoKxnVzWdz5qspyuZNbUvME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly90c3RjcmwuemF0Y2EuZ292LnNhL0NlcnRFbnJvbGwvVFNaRUlOVk9JQ0UtU3ViQ0EtMS5jcmwwga0GCCsGAQUFBwEBBIGgMIGdMG4GCCsGAQUFBzABhmJodHRwOi8vdHN0Y3JsLnphdGNhLmdvdi5zYS9DZXJ0RW5yb2xsL1RTWkVpbnZvaWNlU0NBMS5leHRnYXp0Lmdvdi5sb2NhbF9UU1pFSU5WT0lDRS1TdWJDQS0xKDEpLmNydDArBggrBgEFBQcwAYYfaHR0cDovL3RzdGNybC56YXRjYS5nb3Yuc2Evb2NzcDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMDMCcGCSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwMwCgYIKoZIzj0EAwIDRwAwRAIgOgjNPJW017lsIijmVQVkP7GzFO2KQKd9GHaukLgIWFsCIFJF9uwKhTMxDjWbN+1awsnFI7RLBRxA/6hZ+F1wtaqU"
                Object = ET.SubElement(Signature , "ds:Object"  )
                QualifyingProperties = ET.SubElement(Object , "xades:QualifyingProperties"  )
                QualifyingProperties.set("Target" , "signature")
                QualifyingProperties.set("xmlns:xades" , "http://uri.etsi.org/01903/v1.3.2#")
                SignedProperties = ET.SubElement(QualifyingProperties , "xades:SignedProperties"  )
                SignedProperties.set("Id" , "xadesSignedProperties")
                SignedSignatureProperties = ET.SubElement(SignedProperties , "xades:SignedSignatureProperties"  )
                SigningTime = ET.SubElement(SignedSignatureProperties , "xades:SigningTime"  )
                SigningTime.text = "2024-01-24T11:36:34Z"
                SigningCertificate = ET.SubElement(SignedSignatureProperties , "xades:SigningCertificate"  )
                Cert = ET.SubElement(SigningCertificate , "xades:Cert"  )
                CertDigest = ET.SubElement(Cert , "xades:CertDigest"  )
                Digest_Method2 = ET.SubElement(CertDigest , "ds:DigestMethod"  )
                Digest_Value2 = ET.SubElement(CertDigest , "ds:DigestValue"  )
                Digest_Method2.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Digest_Value2.text = "YTJkM2JhYTcwZTBhZTAxOGYwODMyNzY3NTdkZDM3YzhjY2IxOTIyZDZhM2RlZGJiMGY0NDUzZWJhYWI4MDhmYg=="
                IssuerSerial = ET.SubElement(Cert , "xades:IssuerSerial"  )
                X509IssuerName = ET.SubElement(IssuerSerial , "ds:X509IssuerName"  )
                X509SerialNumber = ET.SubElement(IssuerSerial , "ds:X509SerialNumber"  )
                X509IssuerName.text = "CN=TSZEINVOICE-SubCA-1, DC=extgazt, DC=gov, DC=local"
                X509SerialNumber.text = "2475382886904809774818644480820936050208702411"
                return invoice
            except Exception as e:
                    frappe.throw("error in xml tags formation:  "+ str(e) )

def salesinvoice_data(invoice,invoice_number):
            try:
                sales_invoice_doc = frappe.get_doc('Sales Invoice' ,invoice_number)
                cbc_ProfileID = ET.SubElement(invoice, "cbc:ProfileID")
                cbc_ProfileID.text = "reporting:1.0"
                cbc_ID = ET.SubElement(invoice, "cbc:ID")
                cbc_ID.text = str(sales_invoice_doc.name)
                cbc_UUID = ET.SubElement(invoice, "cbc:UUID")
                cbc_UUID.text =  str(uuid.uuid1())
                uuid1= cbc_UUID.text
                cbc_IssueDate = ET.SubElement(invoice, "cbc:IssueDate")
                cbc_IssueDate.text = str(sales_invoice_doc.posting_date)
                cbc_IssueTime = ET.SubElement(invoice, "cbc:IssueTime")
                cbc_IssueTime.text = get_Issue_Time(invoice_number)
                return invoice ,uuid1 ,sales_invoice_doc
            except Exception as e:
                    frappe.throw("error occured in salesinvoice data"+ str(e) )

def invoice_Typecode_Compliance(invoice,compliance_type):
                    # 0 is default. Not for compliance test. But normal reporting or clearance call.
                    # 1 is for compliance test. Simplified invoice
                    # 2 is for compliance test. Standard invoice
                    # 3 is for compliance test. Simplified Credit Note
                    # 4 is for compliance test. Standard Credit Note
                    # 5 is for compliance test. Simplified Debit Note
                    # 6 is for compliance test. Standard Debit Note
            # frappe.throw(str("here 5 " + str(compliance_type)))
            try:                         
                # cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                # cbc_InvoiceTypeCode.set("name", "0200000")
                # cbc_InvoiceTypeCode.text = "388"
                # return invoice
                 
                if compliance_type == "1":       # simplified invoice
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode") 
                    cbc_InvoiceTypeCode.set("name", "0200000")
                    cbc_InvoiceTypeCode.text = "388"
                    
                elif compliance_type == "2":       # standard invoice
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0100000")
                    cbc_InvoiceTypeCode.text = "388"
                  
                elif compliance_type == "3":       # simplified Credit note
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0200000")
                    cbc_InvoiceTypeCode.text = "381"
                    
                   
                elif compliance_type == "4":       # Standard Credit note
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0100000")
                    cbc_InvoiceTypeCode.text = "381"
                   
                elif compliance_type == "5":       # simplified Debit note
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0211000")
                    cbc_InvoiceTypeCode.text = "383"
                   
                elif compliance_type == "6":       # Standard Debit note
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0100000")
                    cbc_InvoiceTypeCode.text = "383"
                return invoice
                
                
                
            except Exception as e:
                    frappe.throw("error occured in Compliance typecode"+ str(e) )


def invoice_Typecode_Simplified(invoice,sales_invoice_doc):
            try:                             
                cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                if sales_invoice_doc.is_return == 0:         
                    cbc_InvoiceTypeCode.set("name", "0200000") # Simplified
                    cbc_InvoiceTypeCode.text = "388"
                elif sales_invoice_doc.is_return == 1:       # return items and simplified invoice
                    cbc_InvoiceTypeCode.set("name", "0200000")  # Simplified
                    cbc_InvoiceTypeCode.text = "381"  # Credit note
                return invoice
            except Exception as e:
                    frappe.throw("error occured in simplified invoice typecode"+ str(e) )

def invoice_Typecode_Standard(invoice,sales_invoice_doc):
            try:
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0100000") # Standard
                    if sales_invoice_doc.is_return == 0:
                        cbc_InvoiceTypeCode.text = "388"
                    elif sales_invoice_doc.is_return == 1:     # return items and simplified invoice
                        cbc_InvoiceTypeCode.text = "381" # Credit note
                    return invoice
            except Exception as e:
                    frappe.throw("Error in standard invoice type code: "+ str(e))
                    
def doc_Reference(invoice,sales_invoice_doc,invoice_number):
            try:
                cbc_DocumentCurrencyCode = ET.SubElement(invoice, "cbc:DocumentCurrencyCode")
                cbc_DocumentCurrencyCode.text = sales_invoice_doc.currency
                cbc_TaxCurrencyCode = ET.SubElement(invoice, "cbc:TaxCurrencyCode")
                cbc_TaxCurrencyCode.text = "SAR"  # SAR is as zatca requires tax amount in SAR
                if sales_invoice_doc.is_return == 1:
                                invoice=billing_reference_for_credit_and_debit_note(invoice,sales_invoice_doc)
                cac_AdditionalDocumentReference = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:ID")
                cbc_ID_1.text = "ICV"
                cbc_UUID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:UUID")
                cbc_UUID_1.text = str(get_ICV_code(invoice_number))
                return invoice  
            except Exception as e:
                    frappe.throw("Error occured in  reference doc" + str(e) )


def doc_Reference_compliance(invoice,sales_invoice_doc,invoice_number, compliance_type):
            try:
                cbc_DocumentCurrencyCode = ET.SubElement(invoice, "cbc:DocumentCurrencyCode")
                cbc_DocumentCurrencyCode.text = sales_invoice_doc.currency
                cbc_TaxCurrencyCode = ET.SubElement(invoice, "cbc:TaxCurrencyCode")
                cbc_TaxCurrencyCode.text = sales_invoice_doc.currency
                
                if compliance_type == "3" or compliance_type == "4" or compliance_type == "5" or compliance_type == "6":
                
                    cac_BillingReference = ET.SubElement(invoice, "cac:BillingReference")
                    cac_InvoiceDocumentReference = ET.SubElement(cac_BillingReference, "cac:InvoiceDocumentReference")
                    cbc_ID13 = ET.SubElement(cac_InvoiceDocumentReference, "cbc:ID")
                    cbc_ID13.text = "6666666"  # field from return against invoice. 
                
                cac_AdditionalDocumentReference = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:ID")
                cbc_ID_1.text = "ICV"
                cbc_UUID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:UUID")
                cbc_UUID_1.text = str(get_ICV_code(invoice_number))
                return invoice  
            except Exception as e:
                    frappe.throw("Error occured in  reference doc" + str(e) )

def get_pih_for_company(pih_data, company_name):
                
                try:
                    for entry in pih_data.get("data", []):
                        if entry.get("company") == company_name:
                            return entry.get("pih")
                    frappe.throw("Error while retrieving  PIH of company for production:  " + str(e) )
                except Exception as e:
                        frappe.throw("Error in getting PIH of company for production:  " + str(e) )


def additional_Reference(invoice):
            try:
                settings=frappe.get_doc('Zatca setting')
                cac_AdditionalDocumentReference2 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1_1 = ET.SubElement(cac_AdditionalDocumentReference2, "cbc:ID")
                cbc_ID_1_1.text = "PIH"
                cac_Attachment = ET.SubElement(cac_AdditionalDocumentReference2, "cac:Attachment")
                cbc_EmbeddedDocumentBinaryObject = ET.SubElement(cac_Attachment, "cbc:EmbeddedDocumentBinaryObject")
                cbc_EmbeddedDocumentBinaryObject.set("mimeCode", "text/plain")
                
                settings = frappe.get_doc('Zatca setting')
                company_name = settings.company.replace(" ", "-").replace(".", "-").rstrip('.-')
                pih_data = settings.get("pih", "{}")
                pih = get_pih_for_company(pih_data, company_name)
                
                cbc_EmbeddedDocumentBinaryObject.text = pih
                # cbc_EmbeddedDocumentBinaryObject.text = "L0Awl814W4ycuFvjDVL/vIW08mNRNAwqfdlF5i/3dpU="
            # QR CODE ------------------------------------------------------------------------------------------------------------------------------------------------------------------
                cac_AdditionalDocumentReference22 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1_12 = ET.SubElement(cac_AdditionalDocumentReference22, "cbc:ID")
                cbc_ID_1_12.text = "QR"
                cac_Attachment22 = ET.SubElement(cac_AdditionalDocumentReference22, "cac:Attachment")
                cbc_EmbeddedDocumentBinaryObject22 = ET.SubElement(cac_Attachment22, "cbc:EmbeddedDocumentBinaryObject")
                cbc_EmbeddedDocumentBinaryObject22.set("mimeCode", "text/plain")
                cbc_EmbeddedDocumentBinaryObject22.text = "GsiuvGjvchjbFhibcDhjv1886G"
            #END  QR CODE ------------------------------------------------------------------------------------------------------------------------------------------------------------------
                cac_sign = ET.SubElement(invoice, "cac:Signature")
                cbc_id_sign = ET.SubElement(cac_sign, "cbc:ID")
                cbc_method_sign = ET.SubElement(cac_sign, "cbc:SignatureMethod")
                cbc_id_sign.text = "urn:oasis:names:specification:ubl:signature:Invoice"
                cbc_method_sign.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
                return invoice
            except Exception as e:
                    frappe.throw("error occured in additional refrences" + str(e) )

def company_Data(invoice,sales_invoice_doc):
            try:
                company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
                customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                cac_AccountingSupplierParty = ET.SubElement(invoice, "cac:AccountingSupplierParty")
                cac_Party_1 = ET.SubElement(cac_AccountingSupplierParty, "cac:Party")
                cac_PartyIdentification = ET.SubElement(cac_Party_1, "cac:PartyIdentification")
                cbc_ID_2 = ET.SubElement(cac_PartyIdentification, "cbc:ID")
                cbc_ID_2.set("schemeID", "CRN")
                cbc_ID_2.text =company_doc.tax_id   # COmpany CR - Need to have a field in company doctype called company_registration 
                address_list = frappe.get_list("Address", filters={"is_your_company_address": "1"}, fields=["address_line1", "address_line2","city","pincode","state"])
                if len(address_list) == 0:
                    frappe.throw("Zatca requires proper address. Please add your company address in address master")
                for address in address_list:
                    cac_PostalAddress = ET.SubElement(cac_Party_1, "cac:PostalAddress")
                    cbc_StreetName = ET.SubElement(cac_PostalAddress, "cbc:StreetName")
                    cbc_StreetName.text = address.address_line1
                    cbc_BuildingNumber = ET.SubElement(cac_PostalAddress, "cbc:BuildingNumber")
                    cbc_BuildingNumber.text = "6819"
                    cbc_PlotIdentification = ET.SubElement(cac_PostalAddress, "cbc:PlotIdentification")
                    cbc_PlotIdentification.text =  address.address_line1
                    cbc_CitySubdivisionName = ET.SubElement(cac_PostalAddress, "cbc:CitySubdivisionName")
                    cbc_CitySubdivisionName.text = address.address_line2
                    cbc_CityName = ET.SubElement(cac_PostalAddress, "cbc:CityName")
                    cbc_CityName.text = address.city
                    cbc_PostalZone = ET.SubElement(cac_PostalAddress, "cbc:PostalZone")
                    cbc_PostalZone.text = address.pincode
                    cbc_CountrySubentity = ET.SubElement(cac_PostalAddress, "cbc:CountrySubentity")
                    cbc_CountrySubentity.text = address.state
                    break
                cac_Country = ET.SubElement(cac_PostalAddress, "cac:Country")
                cbc_IdentificationCode = ET.SubElement(cac_Country, "cbc:IdentificationCode")
                cbc_IdentificationCode.text = "SA"
                cac_PartyTaxScheme = ET.SubElement(cac_Party_1, "cac:PartyTaxScheme")
                cbc_CompanyID = ET.SubElement(cac_PartyTaxScheme, "cbc:CompanyID")
                cbc_CompanyID.text = company_doc.tax_id
                cac_TaxScheme = ET.SubElement(cac_PartyTaxScheme, "cac:TaxScheme")
                cbc_ID_3 = ET.SubElement(cac_TaxScheme, "cbc:ID")
                cbc_ID_3.text = "VAT"
                cac_PartyLegalEntity = ET.SubElement(cac_Party_1, "cac:PartyLegalEntity")
                cbc_RegistrationName = ET.SubElement(cac_PartyLegalEntity, "cbc:RegistrationName")
                cbc_RegistrationName.text = sales_invoice_doc.company
                return invoice
            except Exception as e:
                    frappe.throw("error occured in company data"+ str(e) )

def customer_Data(invoice,sales_invoice_doc):
            try:
                customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                cac_AccountingCustomerParty = ET.SubElement(invoice, "cac:AccountingCustomerParty")
                cac_Party_2 = ET.SubElement(cac_AccountingCustomerParty, "cac:Party")
                cac_PartyIdentification_1 = ET.SubElement(cac_Party_2, "cac:PartyIdentification")
                cbc_ID_4 = ET.SubElement(cac_PartyIdentification_1, "cbc:ID")
                cbc_ID_4.set("schemeID", "CRN")
                cbc_ID_4.text =customer_doc.tax_id
                if int(frappe.__version__.split('.')[0]) == 15:
                    address = frappe.get_doc("Address", customer_doc.customer_primary_address)    
                else:
                    address = frappe.get_doc("Address", sales_invoice_doc.company_address)
                cac_PostalAddress_1 = ET.SubElement(cac_Party_2, "cac:PostalAddress")
                cbc_StreetName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:StreetName")
                cbc_StreetName_1.text = address.address_line1
                cbc_BuildingNumber_1 = ET.SubElement(cac_PostalAddress_1, "cbc:BuildingNumber")
                cbc_BuildingNumber_1.text = address.address_line2
                cbc_PlotIdentification_1 = ET.SubElement(cac_PostalAddress_1, "cbc:PlotIdentification")
                if hasattr(address, 'po_box'):
                    cbc_PlotIdentification_1.text = address.po_box
                else:
                    cbc_PlotIdentification_1.text = address.address_line1
                cbc_CitySubdivisionName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CitySubdivisionName")
                cbc_CitySubdivisionName_1.text = address.address_line2
                cbc_CityName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CityName")
                cbc_CityName_1.text = address.city
                cbc_PostalZone_1 = ET.SubElement(cac_PostalAddress_1, "cbc:PostalZone")
                cbc_PostalZone_1.text =address.pincode
                cbc_CountrySubentity_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CountrySubentity")
                cbc_CountrySubentity_1.text =address.state
                cac_Country_1 = ET.SubElement(cac_PostalAddress_1, "cac:Country")
                cbc_IdentificationCode_1 = ET.SubElement(cac_Country_1, "cbc:IdentificationCode")
                cbc_IdentificationCode_1.text = "SA" 
                cac_PartyTaxScheme_1 = ET.SubElement(cac_Party_2, "cac:PartyTaxScheme")
                cac_TaxScheme_1 = ET.SubElement(cac_PartyTaxScheme_1, "cac:TaxScheme")
                cbc_ID_5 = ET.SubElement(cac_TaxScheme_1, "cbc:ID")
                cbc_ID_5.text = "VAT"
                cac_PartyLegalEntity_1 = ET.SubElement(cac_Party_2, "cac:PartyLegalEntity")
                cbc_RegistrationName_1 = ET.SubElement(cac_PartyLegalEntity_1, "cbc:RegistrationName")
                cbc_RegistrationName_1.text = sales_invoice_doc.customer
                return invoice
            except Exception as e:
                    frappe.throw("error occured in customer data"+ str(e) )

def delivery_And_PaymentMeans(invoice,sales_invoice_doc, is_return):
            try:
                cac_Delivery = ET.SubElement(invoice, "cac:Delivery")
                cbc_ActualDeliveryDate = ET.SubElement(cac_Delivery, "cbc:ActualDeliveryDate")
                cbc_ActualDeliveryDate.text = str(sales_invoice_doc.due_date)
                cac_PaymentMeans = ET.SubElement(invoice, "cac:PaymentMeans")
                cbc_PaymentMeansCode = ET.SubElement(cac_PaymentMeans, "cbc:PaymentMeansCode")
                cbc_PaymentMeansCode.text = "32"
                
                if is_return == 1:
                    cbc_InstructionNote = ET.SubElement(cac_PaymentMeans, "cbc:InstructionNote")
                    cbc_InstructionNote.text = "Cancellation"    
                return invoice
            except Exception as e:
                    frappe.throw("Delivery and payment means failed"+ str(e) )
def delivery_And_PaymentMeans_for_Compliance(invoice,sales_invoice_doc, compliance_type):
            try:
                cac_Delivery = ET.SubElement(invoice, "cac:Delivery")
                cbc_ActualDeliveryDate = ET.SubElement(cac_Delivery, "cbc:ActualDeliveryDate")
                cbc_ActualDeliveryDate.text = str(sales_invoice_doc.due_date)
                cac_PaymentMeans = ET.SubElement(invoice, "cac:PaymentMeans")
                cbc_PaymentMeansCode = ET.SubElement(cac_PaymentMeans, "cbc:PaymentMeansCode")
                cbc_PaymentMeansCode.text = "32"
                
                if compliance_type == "3" or compliance_type == "4" or compliance_type == "5" or compliance_type == "6":
                    cbc_InstructionNote = ET.SubElement(cac_PaymentMeans, "cbc:InstructionNote")
                    cbc_InstructionNote.text = "Cancellation"    
                return invoice
            except Exception as e:
                    frappe.throw("Delivery and payment means failed"+ str(e) )
                                        
def billing_reference_for_credit_and_debit_note(invoice,sales_invoice_doc):
            try:
                #details of original invoice
                cac_BillingReference = ET.SubElement(invoice, "cac:BillingReference")
                cac_InvoiceDocumentReference = ET.SubElement(cac_BillingReference, "cac:InvoiceDocumentReference")
                cbc_ID13 = ET.SubElement(cac_InvoiceDocumentReference, "cbc:ID")
                cbc_ID13.text = sales_invoice_doc.return_against  # field from return against invoice. 
                
                return invoice
            except Exception as e:
                    frappe.throw("credit and debit note billing failed"+ str(e) )


def tax_Data(invoice,sales_invoice_doc):
    try:

                #for foreign currency
                if sales_invoice_doc.currency != "SAR":
                    cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
                    cbc_TaxAmount_SAR = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
                    cbc_TaxAmount_SAR.set("currencyID", "SAR") # SAR is as zatca requires tax amount in SAR
                    tax_amount_without_retention_sar =  round(sales_invoice_doc.conversion_rate * abs(get_tax_total_from_items(sales_invoice_doc)),2)
                    cbc_TaxAmount_SAR.text = str(round( tax_amount_without_retention_sar,2))     # str( abs(sales_invoice_doc.base_total_taxes_and_charges))
                #end for foreign currency
                
                
                #for SAR currency
                if sales_invoice_doc.currency == "SAR":
                    cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
                    cbc_TaxAmount_SAR = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
                    cbc_TaxAmount_SAR.set("currencyID", "SAR") # SAR is as zatca requires tax amount in SAR
                    tax_amount_without_retention_sar =  round(abs(get_tax_total_from_items(sales_invoice_doc)),2)
                    cbc_TaxAmount_SAR.text = str(round( tax_amount_without_retention_sar,2))     # str( abs(sales_invoice_doc.base_total_taxes_and_charges))
                #end for SAR currency
                
                
        
                cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
                cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
                cbc_TaxAmount.set("currencyID", sales_invoice_doc.currency) # SAR is as zatca requires tax amount in SAR
                tax_amount_without_retention =  round(abs(get_tax_total_from_items(sales_invoice_doc)),2)
                cbc_TaxAmount.text = str(round( tax_amount_without_retention,2))     # str( abs(sales_invoice_doc.base_total_taxes_and_charges))
                cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
                cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount")
                cbc_TaxableAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxableAmount.text =str(abs(round(sales_invoice_doc.base_net_total,2)))
                cbc_TaxAmount_2 = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount")
                cbc_TaxAmount_2.set("currencyID", sales_invoice_doc.currency)
                
                cbc_TaxAmount_2.text = str(tax_amount_without_retention) # str(abs(sales_invoice_doc.base_total_taxes_and_charges))
                cac_TaxCategory_1 = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
                cbc_ID_8 = ET.SubElement(cac_TaxCategory_1, "cbc:ID")
                cbc_ID_8.text =  "S"
                cbc_Percent_1 = ET.SubElement(cac_TaxCategory_1, "cbc:Percent")
                # cbc_Percent_1.text = str(sales_invoice_doc.taxes[0].rate)
                cbc_Percent_1.text = f"{float(sales_invoice_doc.taxes[0].rate):.2f}"                
                cac_TaxScheme_3 = ET.SubElement(cac_TaxCategory_1, "cac:TaxScheme")
                cbc_ID_9 = ET.SubElement(cac_TaxScheme_3, "cbc:ID")
                cbc_ID_9.text = "VAT"
                
                # cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
                # cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
                # cbc_TaxAmount.set("currencyID", sales_invoice_doc.currency)
                # cbc_TaxAmount.text =str(round(tax_amount_without_retention,2))
                
                cac_LegalMonetaryTotal = ET.SubElement(invoice, "cac:LegalMonetaryTotal")
                cbc_LineExtensionAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:LineExtensionAmount")
                cbc_LineExtensionAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_LineExtensionAmount.text =  str(abs(sales_invoice_doc.base_net_total))
                cbc_TaxExclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxExclusiveAmount")
                cbc_TaxExclusiveAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxExclusiveAmount.text = str(abs(sales_invoice_doc.net_total))
                cbc_TaxInclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxInclusiveAmount")
                cbc_TaxInclusiveAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxInclusiveAmount.text = str(round(abs(sales_invoice_doc.net_total) + abs(tax_amount_without_retention),2))
                cbc_AllowanceTotalAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:AllowanceTotalAmount")
                cbc_AllowanceTotalAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_AllowanceTotalAmount.text = str(sales_invoice_doc.base_change_amount)
                cbc_PayableAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableAmount")
                cbc_PayableAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_PayableAmount.text = str(round(abs(sales_invoice_doc.net_total) + abs(tax_amount_without_retention),2))
                return invoice
             
    except Exception as e:
                    frappe.throw("error occured in tax data"+ str(e) )

def get_tax_total_from_items(sales_invoice_doc):
            try:
                total_tax = 0
                for single_item in sales_invoice_doc.items : 
                    item_tax_amount,tax_percent =  get_Tax_for_Item(sales_invoice_doc.taxes[0].item_wise_tax_detail,single_item.item_code)
                    total_tax = total_tax + (single_item.net_amount * (tax_percent/100))
                return total_tax 
            except Exception as e:
                    frappe.throw("Error occured in get_tax_total_from_items "+ str(e) )

def item_data(invoice,sales_invoice_doc):
            try:
                for single_item in sales_invoice_doc.items : 
                    item_tax_amount,item_tax_percentage =  get_Tax_for_Item(sales_invoice_doc.taxes[0].item_wise_tax_detail,single_item.item_code)
                    cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
                    cbc_ID_10 = ET.SubElement(cac_InvoiceLine, "cbc:ID")
                    cbc_ID_10.text = str(single_item.idx)
                    cbc_InvoicedQuantity = ET.SubElement(cac_InvoiceLine, "cbc:InvoicedQuantity")
                    cbc_InvoicedQuantity.set("unitCode", str(single_item.uom))
                    cbc_InvoicedQuantity.text = str(abs(single_item.qty))
                    cbc_LineExtensionAmount_1 = ET.SubElement(cac_InvoiceLine, "cbc:LineExtensionAmount")
                    cbc_LineExtensionAmount_1.set("currencyID", sales_invoice_doc.currency)
                    cbc_LineExtensionAmount_1.text=  str(abs(single_item.base_net_amount))
                    cac_TaxTotal_2 = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
                    cbc_TaxAmount_3 = ET.SubElement(cac_TaxTotal_2, "cbc:TaxAmount")
                    cbc_TaxAmount_3.set("currencyID", sales_invoice_doc.currency)
                    cbc_TaxAmount_3.text = str(abs(round(item_tax_percentage * single_item.base_net_amount / 100,2)))
                    cbc_RoundingAmount = ET.SubElement(cac_TaxTotal_2, "cbc:RoundingAmount")
                    cbc_RoundingAmount.set("currencyID", sales_invoice_doc.currency)
                    cbc_RoundingAmount.text=str(abs(round(single_item.base_net_amount + (item_tax_percentage * single_item.base_net_amount / 100),2)))
                    cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
                    cbc_Name = ET.SubElement(cac_Item, "cbc:Name")
                    cbc_Name.text = single_item.item_code
                    cac_ClassifiedTaxCategory = ET.SubElement(cac_Item, "cac:ClassifiedTaxCategory")
                    cbc_ID_11 = ET.SubElement(cac_ClassifiedTaxCategory, "cbc:ID")
                    cbc_ID_11.text = "S"
                    cbc_Percent_2 = ET.SubElement(cac_ClassifiedTaxCategory, "cbc:Percent")
                    cbc_Percent_2.text = f"{float(item_tax_percentage):.2f}"
                    cac_TaxScheme_4 = ET.SubElement(cac_ClassifiedTaxCategory, "cac:TaxScheme")
                    cbc_ID_12 = ET.SubElement(cac_TaxScheme_4, "cbc:ID")
                    cbc_ID_12.text = "VAT"
                    cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
                    cbc_PriceAmount = ET.SubElement(cac_Price, "cbc:PriceAmount")
                    cbc_PriceAmount.set("currencyID", sales_invoice_doc.currency)
                    cbc_PriceAmount.text =  str(abs(single_item.base_net_rate))
                    
                return invoice
            except Exception as e:
                    frappe.throw("error occured in item data"+ str(e) )

def xml_structuring(invoice,sales_invoice_doc):
            try:
                xml_declaration = "<?xml version='1.0' encoding='UTF-8'?>\n"
                tree = ET.ElementTree(invoice)
                with open(f"xml_files.xml", 'wb') as file:
                    tree.write(file, encoding='utf-8', xml_declaration=True)
                with open(f"xml_files.xml", 'r') as file:
                    xml_string = file.read()
                xml_dom = minidom.parseString(xml_string)
                pretty_xml_string = xml_dom.toprettyxml(indent="  ")   # created xml into formatted xml form 
                with open(f"finalzatcaxml.xml", 'w') as file:
                    file.write(pretty_xml_string)
                          # Attach the getting xml for each invoice
                try:
                    if frappe.db.exists("File",{ "attached_to_name": sales_invoice_doc.name, "attached_to_doctype": sales_invoice_doc.doctype }):
                        frappe.db.delete("File",{ "attached_to_name":sales_invoice_doc.name, "attached_to_doctype": sales_invoice_doc.doctype })
                except Exception as e:
                    frappe.throw(frappe.get_traceback())
                
                try:
                    fileX = frappe.get_doc(
                        {   "doctype": "File",        
                            "file_type": "xml",  
                            "file_name":  "E-invoice-" + sales_invoice_doc.name + ".xml",
                            "attached_to_doctype":sales_invoice_doc.doctype,
                            "attached_to_name":sales_invoice_doc.name, 
                            "content": pretty_xml_string,
                            "is_private": 1,})
                    fileX.save()
                except Exception as e:
                    frappe.throw(frappe.get_traceback())
                
                try:
                    frappe.db.get_value('File', {'attached_to_name':sales_invoice_doc.name, 'attached_to_doctype': sales_invoice_doc.doctype}, ['file_name'])
                except Exception as e:
                    frappe.throw(frappe.get_traceback())
            except Exception as e:
                    frappe.throw("Error occured in XML structuring and attach. Please contact your system administrator"+ str(e) )