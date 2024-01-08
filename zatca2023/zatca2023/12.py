import frappe
import os
frappe.init(site="prod.erpgulf.com")
frappe.connect()
from need import xml_tags,item_data
invoice_number="ACC-SINV-2023-00007"
sales_invoice_doc = frappe.get_doc('Sales Invoice' ,invoice_number)
customer_doc = frappe.get_doc("Customer", sales_invoice_doc.customer)
print(customer_doc.custom_b2c)
# address = frappe.get_doc("Address", company_doc)    
address_list = frappe.get_list("Address", filters={"is_your_company_address": "1"}, fields=["address_line1", "pincode"])
for address in address_list:
    print("Address Line 1:", address.pincode)
    print("Address Line 2:", address.address_line2)
    print()
invoice=xml_tags()
item_data(invoice,sales_invoice_doc)