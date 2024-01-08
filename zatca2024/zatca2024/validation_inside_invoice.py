import frappe
import re
import json
import requests
import base64
from zatca2024.zatca2024.createxml import xml_tags,salesinvoice_data,invoice_Typecode_Simplified,invoice_Typecode_Standard,doc_Reference,additional_Reference ,company_Data,customer_Data,delivery_And_PaymentMeans,tax_Data,item_data,xml_structuring,invoice_Typecode_Compliance,delivery_And_PaymentMeans_for_Compliance,doc_Reference_compliance
from zatca2024.zatca2024.zatcasdkcode import sign_invoice,generate_qr_code,generate_hash,clearance_API,_execute_in_shell,get_API_url,xml_base64_Decode,validate_invoice

@frappe.whitelist(allow_guest=True) 
def zatca_Call_compliance_inside(invoice_number, compliance_type="0"):
                    compliance_type = "0"
                    try:    
                            # create_compliance_x509()
                            # frappe.throw("Created compliance x509 certificate")
                            
                            if not frappe.db.exists("Sales Invoice", invoice_number):
                                frappe.throw("Invoice Number is NOT Valid:  " + str(invoice_number))
                            
                            
                            invoice= xml_tags()
                            invoice,uuid1,sales_invoice_doc=salesinvoice_data(invoice,invoice_number)
                            
                            customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                            
                            
                            if compliance_type == "0":
                                    # frappe.throw(str("here 7 " + str(compliance_type))) 
                                    if customer_doc.custom_b2c == 1:
                                        invoice = invoice_Typecode_Simplified(invoice, sales_invoice_doc)
                                    else:
                                        invoice = invoice_Typecode_Standard(invoice, sales_invoice_doc)
                            else:  # if it a compliance test
                                # frappe.throw(str("here 8 " + str(compliance_type))) 
                                invoice = invoice_Typecode_Compliance(invoice, compliance_type)
                            
                            invoice=doc_Reference(invoice,sales_invoice_doc,invoice_number)
                            invoice=additional_Reference(invoice)
                            invoice=company_Data(invoice,sales_invoice_doc)
                            invoice=customer_Data(invoice,sales_invoice_doc)
                            invoice=delivery_And_PaymentMeans(invoice,sales_invoice_doc, sales_invoice_doc.is_return) 
                            invoice=tax_Data(invoice,sales_invoice_doc)
                            invoice=item_data(invoice,sales_invoice_doc)
                            pretty_xml_string=xml_structuring(invoice,sales_invoice_doc)
                            signed_xmlfile_name,path_string=sign_invoice()
                            hash_value =generate_hash(signed_xmlfile_name,path_string)
                            
                            compliance_api_call_inside(uuid1,hash_value, signed_xmlfile_name )
                    except:       
                            frappe.log_error(title='Zatca Compliance invoice call failed', message=frappe.get_traceback())




def compliance_api_call_inside(uuid1,hash_value, signed_xmlfile_name ):
                # frappe.throw("inside compliance api call")
                try:
                    settings = frappe.get_doc('Zatca setting')
                    payload = json.dumps({
                        "invoiceHash": hash_value,
                        "uuid": uuid1,
                        "invoice": xml_base64_Decode(signed_xmlfile_name) })
                    headers = {
                        'accept': 'application/json',
                        'Accept-Language': 'en',
                        'Accept-Version': 'V2',
                        'Authorization': "Basic" + settings.basic_auth,
                        'Content-Type': 'application/json'  }
                    try:
                        # frappe.throw("inside compliance api call2")
                        response = requests.request("POST", url=get_API_url(base_url="compliance/invoices"), headers=headers, data=payload)
                        frappe.msgprint(response.text)
                        # return response.text

                        if response.status_code != 200:
                            frappe.throw("Error: " + str(response.text))    
                    
                    except Exception as e:
                        frappe.msgprint(str(e))
                        return "error", "NOT ACCEPTED"
                except Exception as e:
                    frappe.throw("ERROR in clearance invoice ,zatca validation:  " + str(e) )