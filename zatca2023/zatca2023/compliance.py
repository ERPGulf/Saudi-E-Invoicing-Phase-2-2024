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
import base64
from frappe.utils import execute_in_shell

def create_compliance_x509(securtity_token):
                try:
                    binarySecurityToken = securtity_token
                    with open(f"cert.pem", 'w') as file:   #attaching X509 certificate
                        file.write(base64.b64decode(binarySecurityToken).decode('utf-8'))
                except Exception as e:
                    frappe.throw( "error in compliance x509" + str(e) )

@frappe.whitelist()
def check_compliance():
            try:
                frappe.msgprint("Check compliance")
                settings=frappe.get_doc('Zatca setting')
                settings.validation_results = settings.validation_results + "Compliance validation settings are here"
                settings.save()
                settings.notify_update()
                # frappe.msgprint("Check compliance")
            except Exception as e:
                    frappe.throw("error occured in check compliance"+ str(e) )
                    
def get_pwd():
    try:
        err,out = execute_in_shell("pwd")
        return out
    except Exception as e:
        frappe.throw("error occured in get pwd"+ str(e) )
        
def set_cert_path():
    try:
        
        new_cert_path = str(get_pwd()) + "/cert.pem"
        new_private_key_path = str(get_pwd()) + "/sdkprivatekey.pem"

        settings=frappe.get_doc('Zatca setting')
        json_file_path = settings.sdk_root + "/Configuration/config.json"
        
        sed_command = (
                f"sed -i -e 's|\\(\"certPath\": \"\\).*\"|\\1{new_cert_path}\"|' "
                f"-e 's|\\(\"privateKeyPath\": \"\\).*\"|\\1{new_private_key_path}\"|' {json_file_path}"
            )
        # sed_command = (
        #     f"sed -i -e 's|(\"certPath\": \").*\"|\\1{new_cert_path}\"|' "
        #     f"-e 's|(\"privateKeyPath\": \").*\"|\\1{new_private_key_path}\"|' "
        #     f"{json_file_path}"
        # )    
        frappe.throw(sed_command)
        # err,out = execute_in_shell(sed_command)
        
        frappe.msgprint("Cert and Private Key path set successfully")
    except Exception as e:
        frappe.throw("Failed to set cert.pem path"+ str(e) ) 
        
        
