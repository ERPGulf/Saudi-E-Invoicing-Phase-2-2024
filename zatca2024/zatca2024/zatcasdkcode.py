import frappe
import os
# frappe.init(site="prod.erpgulf.com")
# frappe.connect()
from zatca2024.zatca2024.createxml import xml_tags,salesinvoice_data,invoice_Typecode_Simplified,invoice_Typecode_Standard,doc_Reference,additional_Reference ,company_Data,customer_Data,delivery_And_PaymentMeans,tax_Data,item_data,xml_structuring,invoice_Typecode_Compliance,delivery_And_PaymentMeans_for_Compliance,doc_Reference_compliance,get_tax_total_from_items
from zatca2024.zatca2024.compliance import get_pwd,set_cert_path,create_compliance_x509,check_compliance
import xml.etree.ElementTree as ET
import base64
from frappe.utils import now
import re
from lxml import etree
import xml.dom.minidom as minidom
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import xml.etree.ElementTree as ElementTree
from frappe.utils import execute_in_shell
import sys
import frappe 
import requests
from frappe.utils.data import  get_time
import base64
import pyqrcode


def clean_up_certificate_string(certificate_string):
    return certificate_string.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----", "").strip()

def get_auth_headers(certificate=None, secret=None):
    if certificate and secret:
        certificate_stripped = clean_up_certificate_string(certificate)
        certificate_base64 = base64.b64encode(certificate_stripped.encode()).decode()
        credentials = f"{certificate_base64}:{secret}"
        basic_token = base64.b64encode(credentials.encode()).decode()
        return basic_token       
    return {}

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

def get_latest_generated_csr_file(folder_path='.'):
            try:
                files = [f for f in os.listdir(folder_path) if f.startswith("generated-csr") and os.path.isfile(os.path.join(folder_path, f))]
                if not files:
                    return None
                latest_file = max(files, key=os.path.getmtime)
                print(latest_file)
                return os.path.join(folder_path, latest_file)
            except Exception as e:
                    frappe.throw(" error in get_latest_generated_csr_file: "+ str(e) )


@frappe.whitelist(allow_guest=True)
def generate_csr():
            try:
                settings=frappe.get_doc('Zatca setting')
                csr_config_file = 'sdkcsrconfig.properties'
                private_key_file = 'sdkprivatekey.pem'
                generated_csr_file = 'sdkcsr.pem'
                SDK_ROOT=settings.sdk_root
                path_string=f"export SDK_ROOT={SDK_ROOT} && export FATOORA_HOME=$SDK_ROOT/Apps && export SDK_CONFIG=config.json && export PATH=$PATH:$FATOORA_HOME &&  "
                
                if settings.select == "Simulation":
                    command_generate_csr =  path_string  + f'fatoora -sim -csr -csrConfig {csr_config_file} -privateKey {private_key_file} -generatedCsr {generated_csr_file} -pem'
                else:
                    command_generate_csr =  path_string  + f'fatoora -csr -csrConfig {csr_config_file} -privateKey {private_key_file} -generatedCsr {generated_csr_file} -pem'
                
                try:
                    err,out = _execute_in_shell(command_generate_csr)
                    frappe.msgprint(out)
                    with open(get_latest_generated_csr_file(), "r") as file_csr:
                        get_csr = file_csr.read()
                    file = frappe.get_doc({
                            "doctype": "File",
                            "file_name": f"generated-csr-{settings.name}.csr",
                            "attached_to_doctype": settings.doctype,
                            "attached_to_name": settings.name,
                            "content": get_csr 
                            })
                    file.save(ignore_permissions=True)
                    frappe.msgprint("CSR generation successful. CSR saved")
                except Exception as e:
                    frappe.throw(err)
                    frappe.throw("An error occurred: " + str(e))
            except Exception as e:
                    frappe.throw("error occured in generate csr"+ str(e) )


def get_API_url(base_url):
                try:
                    settings = frappe.get_doc('Zatca setting')
                    if settings.select == "Sandbox":
                        url = settings.sandbox_url + base_url
                    elif settings.select == "Simulation":
                        url = settings.simulation_url + base_url
                    else:
                        url = settings.production_url + base_url
                    return url 
                except Exception as e:
                    frappe.throw(" getting url failed"+ str(e) ) 

@frappe.whitelist(allow_guest=True)
def create_CSID(): 
                try:
                    # set_cert_path()
                    settings=frappe.get_doc('Zatca setting')     
                    with open(get_latest_generated_csr_file(), "r") as f:
                        csr_contents = f.read()
                    payload = json.dumps({
                    "csr": csr_contents
                    })
                    headers = {
                    'accept': 'application/json',
                    'OTP': settings.otp,
                    'Accept-Version': 'V2',
                    'Content-Type': 'application/json',
                    'Cookie': 'TS0106293e=0132a679c07382ce7821148af16b99da546c13ce1dcddbef0e19802eb470e539a4d39d5ef63d5c8280b48c529f321e8b0173890e4f'
                    }
                    # frappe.throw(csr_contents)
                    response = requests.request("POST", url=get_API_url(base_url="compliance"), headers=headers, data=payload)
                    # response.status_code = 400
                    if response.status_code == 400:
                        frappe.throw("Error: " + "OTP is not valid", response.text)
                    if response.status_code != 200:
                        frappe.throw("Error: " + "Error in Certificate or OTP: " + "<br> <br>" + response.text)
                    
                    # frappe.msgprint(str(response.content))
                    frappe.msgprint("Successfully created CSR.")
                    data=json.loads(response.text)
                    # compliance_cert =get_auth_headers(data["binarySecurityToken"],data["secret"])
                    concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
                    encoded_value = base64.b64encode(concatenated_value.encode()).decode()

                    with open(f"cert.pem", 'w') as file:   #attaching X509 certificate
                        file.write(base64.b64decode(data["binarySecurityToken"]).decode('utf-8'))

                    settings.set("basic_auth", encoded_value)
                    settings.save(ignore_permissions=True)
                    settings.set("compliance_request_id",data["requestID"])
                    settings.save(ignore_permissions=True)
                except Exception as e:
                            frappe.throw("error in csid formation: " + str(e))

                    
def sign_invoice():
                try:
                    settings=frappe.get_doc('Zatca setting')
                    xmlfile_name = 'finalzatcaxml.xml'
                    signed_xmlfile_name = 'sdsign.xml'
                    SDK_ROOT= settings.sdk_root
                    path_string=f"export SDK_ROOT={SDK_ROOT} && export FATOORA_HOME=$SDK_ROOT/Apps && export SDK_CONFIG=config.json && export PATH=$PATH:$FATOORA_HOME &&  "
                    
                    command_sign_invoice = path_string  + f'fatoora -sign -invoice {xmlfile_name} -signedInvoice {signed_xmlfile_name}'
                    # frappe.throw(command_sign_invoice)
                except Exception as e:
                    frappe.throw("While signing invoice An error occurred, inside sign_invoice : " + str(e))
                
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
            
def generate_qr_code(signed_xmlfile_name,sales_invoice_doc,path_string):
                try:
                    with open(signed_xmlfile_name, 'r') as file:
                        file_content = file.read()
                    command_generate_qr =path_string  + f'fatoora -qr -invoice {signed_xmlfile_name}'
                    err,out = _execute_in_shell(command_generate_qr)
                    qr_code_match = re.search(r'QR code = (.+)', out.decode("utf-8"))
                    if qr_code_match:
                        qr_code_value = qr_code_match.group(1)
                        # frappe.msgprint("QR Code Value: " + qr_code_value) 
                        return qr_code_value
                    else:
                        frappe.msgprint("QR Code not found in the output.")    
                except Exception as e:
                    frappe.throw(f"Errorin generating qr:{e} ")
                    return None
           
def generate_hash(signed_xmlfile_name,path_string):
                try:
                    command_generate_hash = path_string  + f'fatoora -generateHash -invoice {signed_xmlfile_name}'
                    err,out = _execute_in_shell(command_generate_hash)
                    invoice_hash_match = re.search(r'INVOICE HASH = (.+)', out.decode("utf-8"))
                    if invoice_hash_match:
                        hash_value = invoice_hash_match.group(1)
                        # frappe.msgprint("The hash value: " + hash_value)
                        return hash_value
                    else:
                        frappe.msgprint("Hash value not found in the log entry.")
                except Exception as e:
                    frappe.throw(f"Error in generate hash:{e} ")
                        
def validate_invoice(signed_xmlfile_name,path_string):               
                try:
                        command_validate_hash = path_string  + f'fatoora -validate -invoice {signed_xmlfile_name}'
                        err,out = _execute_in_shell(command_validate_hash)
                        pattern_global_result = re.search(r'\*\*\* GLOBAL VALIDATION RESULT = (\w+)', out.decode("utf-8"))
                        global_result = pattern_global_result.group(1) if pattern_global_result else None
                        global_validation_result = 'PASSED' if global_result == 'PASSED' else 'FAILED'
                        if global_validation_result == 'FAILED':
                            frappe.msgprint(out)
                            frappe.msgprint(err)
                            frappe.msgprint("Validation has been failed")
                        else:
                            frappe.msgprint(out)
                            frappe.msgprint(err)
                            frappe.msgprint("Validation has been done Successfully")
                except Exception as e:
                            frappe.throw(f"An error occurred validate invoice: {str(e)}")  
               
def get_Clearance_Status(result):
                    try:
                        json_data = json.loads(result.text)
                        clearance_status = json_data.get("clearanceStatus")
                        print("clearance status: " + clearance_status)
                        return clearance_status
                    except Exception as e:
                        print(e) 
                        
def xml_base64_Decode(signed_xmlfile_name):
                    try:
                        with open(signed_xmlfile_name, "r") as file:
                                        xml = file.read().lstrip()
                                        base64_encoded = base64.b64encode(xml.encode("utf-8"))
                                        base64_decoded = base64_encoded.decode("utf-8")
                                        return base64_decoded
                    except Exception as e:
                        frappe.throw("Error in xml base64:  " + str(e) )

def compliance_api_call(uuid1,hash_value, signed_xmlfile_name ):
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

@frappe.whitelist(allow_guest=True)                   
def production_CSID():    
                try:
                    settings = frappe.get_doc('Zatca setting')
                    payload = json.dumps({
                    "compliance_request_id": settings.compliance_request_id })
                   
                    headers = {
                    'accept': 'application/json',
                    'Accept-Version': 'V2',
                    'Authorization': 'Basic'+ settings.basic_auth,
                    # 'Authorization': 'Basic'+ "VkZWc1NsRXhTalpSTUU1Q1dsaHNibEZZWkVwUmEwWnVVMVZrUWxkWWJGcFhhazAxVTJzeFFtSXdaRVJSTTBaSVZUQXdNRTlWU2tKVVZVNU9VV3hXTkZKWWNFSlZhMHB1Vkd4YVExRlZNVTVSTWpGWFUyMUtkVmR1V21oV01EVjNXVzB4YW1Rd2FHOVpNRFZPWVdzeE5GUlhjRXBsYXpGeFVWaHdVRlpGYkRaV01taHFWR3N4Y1ZvemFFNWhhMncxVkZkd1JtUXdNVVZSV0dSWVlXdEpNVlJXUm5wa01FNVNWMVZTVjFWV1JraFNXR1JMVmtaR1ZWSldiRTVSYkd4SVVWUkdWbEpWVGpOa01VSk9aV3RHTTFReFVtcGtNRGxGVVZSS1RsWkZSak5VVlZKQ1pXc3hWRm96WkV0YU1XeEZWbXhHVWxNd1VrTlBWVXBzVWpKNE5sTlZWbk5rVjAxNlVXMTRXazB4U25kWmFra3dXakZGZVU5WVZtdFRSWEJ2VjFST1UyTkhTblJaTW1SVVlrVTFSVlJXVGxwa01IQkNWMVZTVjFWV1JrVlNSVWw0VmxaVmVGVllVbEJTUjJONVZHdFNUbVZGTVZWVlZFWk5Wa1V4TTFSVlVuSk5NREZGV2pOa1QyRnJWak5VVlZKQ1pEQXhObEZzWkU1UmEwWklVVzVzZUZJeFRrNU9SR3hDV2pCV1NGRnNUakZSYTBwQ1VWVjBRazFGYkVKUmEzaFNZVWhDV1UxRlNrVmtSVVpTVDFWS05rOUhaM2ROYms1M1ZrWkdTbFZWVGpKT1YyYzBWRmhHTkdGRVVuQlRSVEYzVVcwNGRsRnRPWEJXUm1ScllsTjBVMWRYV2t0aVZYQlBaR3BrV1dSdVZUVk5NbHAyVjFjME1FNVVhRTlTTVVwdVltNW5NazVIV2xkaGJUbFdUREZDTVdGdFpHcFhXR1J1V1RBeE0xSkZSbHBTUmxwVFRVWlNRbFZWWjNaUmEwWktaREJHUlZFd1NucGFNV3hGVm14SmQxVnJTa3BTTTBaT1UxVmtkV05GYkVoaE1ERktVakpvVGxaSVRqTlVNVVphVWtaYVVsVlZWa1ZTUld3MFZFWmFVMVpHV2tsa00yeE5WbXhLVlZacmFETmxhM2hZVm0xMFRtRnJjSFJVVm1SU1RrVjRXRlpVU2xwV1JXd3dWRlpTUm1WRk9VUk5SRlphWVd4Vk1GUkdaRkpPVm14VllVY3hUbFpGV25OVWExSlNUVlp3Y1ZKWFdrNVJha0pJVVRKa2RGVXdjSFppVmxFMFlWaG9jbEZXUmtaVVZWSTJWRmhrVGxKSGMzcFVWVkp1WkRBMWNWSllaRTVTUlVZelZGaHdSbFJyTVVKak1HUkNUVlpXUmxKRlJqTlNWVEZWVWxob1RsWkZWbE5VVlVVMFVqQkZlRlpWVmtoYU0yUktWbGQ0UzFVeFNrVlRWRlpPWVcxME5GTkljRUphUlVwdVZHeGFRMUZVYUU1U2JYaExZa1pzV0dReVpHRlhSVFIzVjFab1UySkZiRWhTYlhCclVqSjNlVmxXYUZOalJuQlpWRmhrUkZveGJFcFRNamxoVTFod2NVMUZWa0prTUd4RlZURkdRbVF4U201VFYyaENWRmhHVTFOclJYSlZSRTVKVkVac2FWUXdNRFJPVldoTFRETmtUMlZ0UmxkT01XUnFXbTVKZGxkcVRqRmpWR3hMVFRCV1ZHTnNXbHBsYTBad1VsVkdkazV0YUdwUFZGSlRVMGR3YldRelRuZFpVemwzVjBaYWRWWnBPWFpWVjBaT1QxUk9hVTVzU1RKaVYyUmhWMFJDTVZGV1RYbE5WVnB1VUZFOVBRPT06eXRabHl6YklXY0wrUHlETytFd1JqWHRHSEp4SHB3cXdJYUVsaGxMQVJZQT0=",
                    # 'Authorization': 'Basic'+ "VFVsSlExSjZRME5CWlhsblFYZEpRa0ZuU1VkQldYbFpXak01U2sxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWsxNFRXcEplazFxUVhwUFZFbDZWMmhqVGsxcVozaE5ha2w1VFdwRmQwMUVRWGRYYWtJMVRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWbE5RbGxIUVRGVlJVTjNkMUJOZWtGM1QxUmpkMDlFUVRKTlZFRjNUVVJCZWsxVFozZEtaMWxFVmxGUlMwUkNPVUpsUjJ4NlNVVnNkV016UW14Wk0xSndZakkwWjFFeU9YVmtTRXBvV1ROU2NHSnRZMmRUYkU1RVRWTlpkMHBCV1VSV1VWRkVSRUl4VlZVeFVYUlBSR2N5VGtSTmVFMVVVVEZNVkUxM1RVUnJNMDFFWjNkT2FrVjNUVVJCZDAxNlFsZE5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVV0Qk1FbEJRa3hSYUhCWU1FSkVkRUZST1VKNk9HZ3dNbk53VkZGSlVVTjJOV2c0VFhGNGFEUnBTRTF3UW04dlFtOXBWRmRrYlN0U1dXWktiVXBPZGpkWWRuVTVNMlp2V1c0ME5UaE9SMUpuYm5nMk5HWldhbTlWTDFCMWFtZGpXWGRuWTAxM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVEwSnpaMWxFVmxJd1VrSkpSM0ZOU1VkdWNFbEhhMDFKUjJoTlZITjNUMUZaUkZaUlVVVkVSRWw0VEZaU1ZGWklkM2xNVmxKVVZraDNla3hYVm10TmFrcHRUVmRSTkV4WFZUSlpWRWwwVFZSRmVFOURNRFZaYWxVMFRGZFJOVmxVYUcxTlZFWnNUa1JSTVZwcVJXWk5RakJIUTJkdFUwcHZiVlE0YVhoclFWRkZUVVI2VFhkTlJHc3pUVVJuZDA1cVJYZE5SRUYzVFhwRlRrMUJjMGRCTVZWRlJFRjNSVTFVUlhoTlZFVlNUVUU0UjBFeFZVVkhaM2RKVld4S1UxSkVTVFZOYW10NFNIcEJaRUpuVGxaQ1FUaE5SbXhLYkZsWGQyZGFXRTR3V1ZoU2JFbEhSbXBrUjJ3eVlWaFNjRnBZVFhkRFoxbEpTMjlhU1hwcU1FVkJkMGxFVTFGQmQxSm5TV2hCVFhGU1NrRXJVRE5JVEZsaVQwMDROVWhLTDNkT2VtRldOMWRqWm5JdldqTjFjVGxLTTBWVGNsWlpla0ZwUlVGdk5taGpPVFJTU0dwbWQzTndZUzl3V0ZadVZpOXZVV0ZOT1ROaU5sSTJiV2RhV0RCMVFWTXlNVVpuUFE9PTp5dFpseXpiSVdjTCtQeURPK0V3UmpYdEdISnhIcHdxd0lhRWxobExBUllBPQ==",
                    'Content-Type': 'application/json' }
                    response = requests.request("POST", url=get_API_url(base_url="production/csids"), headers=headers, data=payload)
                    if response.status_code != 200:
                        frappe.throw("Error: " + str(response.text))
                    data=json.loads(response.text)
                    concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
                    encoded_value = base64.b64encode(concatenated_value.encode()).decode()
                    with open(f"cert.pem", 'w') as file:   #attaching X509 certificate
                        file.write(base64.b64decode(data["binarySecurityToken"]).decode('utf-8'))
                    settings.set("basic_auth_production", encoded_value)
                    settings.save(ignore_permissions=True)
                except Exception as e:
                    frappe.throw("error in  production csid formation:  " + str(e) )

def get_Reporting_Status(result):
                    try:
                        json_data = json.loads(result.text)
                        reporting_status = json_data.get("reportingStatus")
                        print("reportingStatus: " + reporting_status)
                        return reporting_status
                    except Exception as e:
                        print(e) 

def success_Log(response,uuid1,invoice_number):
                    try:
                        current_time = frappe.utils.now()
                        frappe.get_doc({
                            "doctype": "Zatca Success log",
                            "title": "Zatca invoice call done successfully",
                            "message": "This message by Zatca Compliance",
                            "uuid": uuid1,
                            "invoice_number": invoice_number,
                            "time": current_time,
                            "zatca_response": response  
                            
                        }).insert(ignore_permissions=True)
                    except Exception as e:
                        frappe.throw("Error in success log  " + str(e))

def error_Log():
                    try:
                        frappe.log_error(title='Zatca invoice call failed in clearance status',message=frappe.get_traceback())
                    except Exception as e:
                        frappe.throw("Error in error log  " + str(e))   

def attach_QR_Image_For_Reporting(qr_code_value,sales_invoice_doc):
                    try:
                            qr = pyqrcode.create(qr_code_value)
                            temp_file_path = "qr_code_value.png"
                            qr.png(temp_file_path, scale=5)
                            file = frappe.get_doc({
                                "doctype": "File",
                                "file_name": f"QR_image_{sales_invoice_doc.name}.png",
                                "attached_to_doctype": sales_invoice_doc.doctype,
                                "attached_to_name": sales_invoice_doc.name,
                                "content": open(temp_file_path, "rb").read()
                               
                            })
                            file.save(ignore_permissions=True)
                    except Exception as e:
                        frappe.throw("Error in qr image attach for reporting api   " + str(e))   

def reporting_API(uuid1,hash_value,signed_xmlfile_name,invoice_number,sales_invoice_doc):
                    try:
                        settings = frappe.get_doc('Zatca setting')
                        payload = json.dumps({
                        "invoiceHash": hash_value,
                        "uuid": uuid1,
                        "invoice": xml_base64_Decode(signed_xmlfile_name),
                        })
                        headers = {
                        'accept': 'application/json',
                        'accept-language': 'en',
                        'Clearance-Status': '0',
                        'Accept-Version': 'V2',
                        # 'Authorization': "Basic VFVsSlJESjZRME5CTkVOblFYZEpRa0ZuU1ZSaWQwRkJaSEZFYlVsb2NYTnFjRzAxUTNkQlFrRkJRakp2UkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJOZVU5RVJURk9SRmw2VFd4dldFUlVTWGxOUkUxNlRVUkZNVTVFV1hwTmJHOTNWRlJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1ZYQm9ZMjFzZVUxU2IzZEhRVmxFVmxGUlRFVjRSa3RhVjFKcldWZG5aMUZ1U21oaWJVNXZUVlJKZWs1RVJWTk5Ra0ZIUVRGVlJVRjRUVXBOVkVrelRHcEJkVTFETkhoTlJsbDNSVUZaU0V0dldrbDZhakJEUVZGWlJrczBSVVZCUVc5RVVXZEJSVVF2ZDJJeWJHaENka0pKUXpoRGJtNWFkbTkxYnpaUGVsSjViWGx0VlRsT1YxSm9TWGxoVFdoSFVrVkNRMFZhUWpSRlFWWnlRblZXTW5oWWFYaFpOSEZDV1dZNVpHUmxjbnByVnpsRWQyUnZNMGxzU0dkeFQwTkJhVzkzWjJkSmJVMUpSMHhDWjA1V1NGSkZSV2RaVFhkbldVTnJabXBDT0UxU2QzZEhaMWxFVmxGUlJVUkNUWGxOYWtsNVRXcE5lVTVFVVRCTmVsRjZZVzFhYlU1RVRYbE5VamgzU0ZGWlMwTmFTVzFwV2xCNVRFZFJRa0ZSZDFCTmVrVjNUVlJqTVUxNmF6Tk9SRUYzVFVSQmVrMVJNSGREZDFsRVZsRlJUVVJCVVhoTlJFVjRUVkpGZDBSM1dVUldVVkZoUkVGb1ZGbFhNWGRpUjFWblVsUkZXazFDWTBkQk1WVkZSSGQzVVZVeVJuUmpSM2hzU1VWS01XTXpUbkJpYlZaNlkzcEJaRUpuVGxaSVVUUkZSbWRSVldoWFkzTmlZa3BvYWtRMVdsZFBhM2RDU1V4REszZE9WbVpMV1hkSWQxbEVWbEl3YWtKQ1ozZEdiMEZWWkcxRFRTdDNZV2R5UjJSWVRsb3pVRzF4ZVc1TE5Xc3hkRk00ZDFSbldVUldVakJtUWtWamQxSlVRa1J2UlVkblVEUlpPV0ZJVWpCalJHOTJURE5TZW1SSFRubGlRelUyV1ZoU2FsbFROVzVpTTFsMVl6SkZkbEV5Vm5sa1JWWjFZMjA1YzJKRE9WVlZNWEJHVTFVMVYxUXdiRVJTVXpGVVpGZEtSRkZUTUhoTWJVNTVZa1JEUW5KUldVbExkMWxDUWxGVlNFRlJSVVZuWVVGM1oxb3dkMkpuV1VsTGQxbENRbEZWU0UxQlIwZFpiV2d3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NRTVzWTI1U1JtSnVTblppUjNkMlZrWk9ZVkpYYkhWa2JUbHdXVEpXVkZFd1JYaE1iVlkwWkVka2FHVnVVWFZhTWpreVRHMTRkbGt5Um5OWU1WSlVWMnRXU2xSc1dsQlRWVTVHVEZaT01WbHJUa0pNVkVWdlRWTnJkVmt6U2pCTlEzTkhRME56UjBGUlZVWkNla0ZDYUdnNWIyUklVbmRQYVRoMlpFaE9NRmt6U25OTWJuQm9aRWRPYUV4dFpIWmthVFY2V1ZNNWRsa3pUbmROUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKU0dkRVFXUkNaMDVXU0ZOVlJVWnFRVlZDWjJkeVFtZEZSa0pSWTBSQloxbEpTM2RaUWtKUlZVaEJkMDEzU25kWlNrdDNXVUpDUVVkRFRuaFZTMEpDYjNkSFJFRkxRbWRuY2tKblJVWkNVV05FUVdwQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVV0Q1oyZHhhR3RxVDFCUlVVUkJaMDVLUVVSQ1IwRnBSVUY1VG1oNVkxRXpZazVzVEVaa1QxQnNjVmxVTmxKV1VWUlhaMjVMTVVkb01FNUlaR05UV1RSUVprTXdRMGxSUTFOQmRHaFlkblkzZEdWMFZVdzJPVmRxY0RoQ2VHNU1URTEzWlhKNFdtaENibVYzYnk5blJqTkZTa0U5UFE9PTpmOVlSaG9wTi9HN3gwVEVDT1k2bktTQ0hMTllsYjVyaUFIU0ZQSUNvNHF3PQ==" ,
                        # 'Authorization': "Basic VFVsSlJESjZRME5CTkVOblFYZEpRa0ZuU1ZSaWQwRkJaSEZFYlVsb2NYTnFjRzAxUTNkQlFrRkJRakp2UkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJOZVU5RVJURk9SRmw2VFd4dldFUlVTWGxOUkUxNlRVUkZNVTVFV1hwTmJHOTNWRlJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1ZYQm9ZMjFzZVUxU2IzZEhRVmxFVmxGUlRFVjRSa3RhVjFKcldWZG5aMUZ1U21oaWJVNXZUVlJKZWs1RVJWTk5Ra0ZIUVRGVlJVRjRUVXBOVkVrelRHcEJkVTFETkhoTlJsbDNSVUZaU0V0dldrbDZhakJEUVZGWlJrczBSVVZCUVc5RVVXZEJSVVF2ZDJJeWJHaENka0pKUXpoRGJtNWFkbTkxYnpaUGVsSjViWGx0VlRsT1YxSm9TWGxoVFdoSFVrVkNRMFZhUWpSRlFWWnlRblZXTW5oWWFYaFpOSEZDV1dZNVpHUmxjbnByVnpsRWQyUnZNMGxzU0dkeFQwTkJhVzkzWjJkSmJVMUpSMHhDWjA1V1NGSkZSV2RaVFhkbldVTnJabXBDT0UxU2QzZEhaMWxFVmxGUlJVUkNUWGxOYWtsNVRXcE5lVTVFVVRCTmVsRjZZVzFhYlU1RVRYbE5VamgzU0ZGWlMwTmFTVzFwV2xCNVRFZFJRa0ZSZDFCTmVrVjNUVlJqTVUxNmF6Tk9SRUYzVFVSQmVrMVJNSGREZDFsRVZsRlJUVVJCVVhoTlJFVjRUVkpGZDBSM1dVUldVVkZoUkVGb1ZGbFhNWGRpUjFWblVsUkZXazFDWTBkQk1WVkZSSGQzVVZVeVJuUmpSM2hzU1VWS01XTXpUbkJpYlZaNlkzcEJaRUpuVGxaSVVUUkZSbWRSVldoWFkzTmlZa3BvYWtRMVdsZFBhM2RDU1V4REszZE9WbVpMV1hkSWQxbEVWbEl3YWtKQ1ozZEdiMEZWWkcxRFRTdDNZV2R5UjJSWVRsb3pVRzF4ZVc1TE5Xc3hkRk00ZDFSbldVUldVakJtUWtWamQxSlVRa1J2UlVkblVEUlpPV0ZJVWpCalJHOTJURE5TZW1SSFRubGlRelUyV1ZoU2FsbFROVzVpTTFsMVl6SkZkbEV5Vm5sa1JWWjFZMjA1YzJKRE9WVlZNWEJHVTFVMVYxUXdiRVJTVXpGVVpGZEtSRkZUTUhoTWJVNTVZa1JEUW5KUldVbExkMWxDUWxGVlNFRlJSVVZuWVVGM1oxb3dkMkpuV1VsTGQxbENRbEZWU0UxQlIwZFpiV2d3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NRTVzWTI1U1JtSnVTblppUjNkMlZrWk9ZVkpYYkhWa2JUbHdXVEpXVkZFd1JYaE1iVlkwWkVka2FHVnVVWFZhTWpreVRHMTRkbGt5Um5OWU1WSlVWMnRXU2xSc1dsQlRWVTVHVEZaT01WbHJUa0pNVkVWdlRWTnJkVmt6U2pCTlEzTkhRME56UjBGUlZVWkNla0ZDYUdnNWIyUklVbmRQYVRoMlpFaE9NRmt6U25OTWJuQm9aRWRPYUV4dFpIWmthVFY2V1ZNNWRsa3pUbmROUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKU0dkRVFXUkNaMDVXU0ZOVlJVWnFRVlZDWjJkeVFtZEZSa0pSWTBSQloxbEpTM2RaUWtKUlZVaEJkMDEzU25kWlNrdDNXVUpDUVVkRFRuaFZTMEpDYjNkSFJFRkxRbWRuY2tKblJVWkNVV05FUVdwQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVV0Q1oyZHhhR3RxVDFCUlVVUkJaMDVLUVVSQ1IwRnBSVUY1VG1oNVkxRXpZazVzVEVaa1QxQnNjVmxVTmxKV1VWUlhaMjVMTVVkb01FNUlaR05UV1RSUVprTXdRMGxSUTFOQmRHaFlkblkzZEdWMFZVdzJPVmRxY0RoQ2VHNU1URTEzWlhKNFdtaENibVYzYnk5blJqTkZTa0U5UFE9PTpmOVlSaG9wTi9HN3gwVEVDT1k2bktTQ0hMTllsYjVyaUFIU0ZQSUNvNHF3PQ==",
                        # 'Authorization': 'Basic' + settings.basic_auth_production,
                        'Authorization': 'Basic' + settings.basic_auth_production,
                        'Content-Type': 'application/json',
                        'Cookie': 'TS0106293e=0132a679c0639d13d069bcba831384623a2ca6da47fac8d91bef610c47c7119dcdd3b817f963ec301682dae864351c67ee3a402866'
                        }
                        try:
                            response = requests.request("POST", url=get_API_url(base_url="invoices/reporting/single"), headers=headers, data=payload)
                      
                            if response.status_code  in (400,405,406,409 ):
                                invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number )
                                invoice_doc.db_set('custom_uuid' , 'Not Submitted' , commit=True  , update_modified=True)
                                invoice_doc.db_set('custom_zatca_status' , 'Not Submitted' , commit=True  , update_modified=True)

                                frappe.throw("Error: The request you are sending to Zatca is in incorrect format. Please report to system administrator . Status code:  " + str(response.status_code) + "<br><br> " + response.text )            
                            
                            
                            if response.status_code  in (401,403,407,451 ):
                                invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number  )
                                invoice_doc.db_set('custom_uuid' , 'Not Submitted' , commit=True  , update_modified=True)
                                invoice_doc.db_set('custom_zatca_status' , 'Not Submitted' , commit=True  , update_modified=True)

                              
                                frappe.throw("Error: Zatca Authentication failed. Your access token may be expired or not valid. Please contact your system administrator. Status code:  " + str(response.status_code) + "<br><br> " + response.text)            
                            
                            if response.status_code not in (200, 202):
                                invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number  )
                                invoice_doc.db_set('custom_uuid' , 'Not Submitted' , commit=True  , update_modified=True)
                                invoice_doc.db_set('custom_zatca_status' , 'Not Submitted' , commit=True  , update_modified=True)
                                
                               
                                frappe.throw("Error: Zatca server busy or not responding. Try after sometime or contact your system administrator. Status code:  " + str(response.status_code)+ "<br><br> " + response.text )
                            
                            
                            
                            if response.status_code  in (200, 202):
                                if response.status_code == 202:
                                    msg = "REPORTED WITH WARNIGS: <br> <br> Please copy the below message and send it to your system administrator to fix this warnings before next submission <br>  <br><br> "
                                
                                if response.status_code == 200:
                                    msg = "SUCCESS: <br>   <br><br> "
                                
                                msg = msg + "Status Code: " + str(response.status_code) + "<br><br> "
                                msg = msg + "Zatca Response: " + response.text + "<br><br> "
                                frappe.msgprint(msg)
                                settings.pih = hash_value
                                settings.save(ignore_permissions=True)
                                
                                invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number )
                                invoice_doc.db_set('custom_uuid' , uuid1 , commit=True  , update_modified=True)
                                invoice_doc.db_set('custom_zatca_status' , 'REPORTED' , commit=True  , update_modified=True)

                               
                                # frappe.msgprint(xml_cleared)
                                success_Log(response.text,uuid1, invoice_number)
                                
                            else:
                                error_Log()
                        except Exception as e:
                            frappe.throw("Error in reporting api-2:  " + str(e) )
    
                    except Exception as e:
                        frappe.throw("Error in reporting api-1:  " + str(e) )

def clearance_API(uuid1,hash_value,signed_xmlfile_name,invoice_number,sales_invoice_doc):
                    try:
                        # frappe.msgprint("Clearance API")
                        settings = frappe.get_doc('Zatca setting')
                        payload = json.dumps({
                        "invoiceHash": hash_value,
                        "uuid": uuid1,
                        "invoice": xml_base64_Decode(signed_xmlfile_name), })
                        headers = {
                        'accept': 'application/json',
                        'accept-language': 'en',
                        'Clearance-Status': '1',
                        'Accept-Version': 'V2',
                        'Authorization': 'Basic' + settings.basic_auth_production,
                        # 'Authorization': 'Basic' + settings.basic_auth,
                        
                        'Content-Type': 'application/json',
                        'Cookie': 'TS0106293e=0132a679c03c628e6c49de86c0f6bb76390abb4416868d6368d6d7c05da619c8326266f5bc262b7c0c65a6863cd3b19081d64eee99' }
                        
                        response = requests.request("POST", url=get_API_url(base_url="invoices/clearance/single"), headers=headers, data=payload)
                        
                        # response.status_code = 400
                        
                        if response.status_code  in (400,405,406,409 ):
                            invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number  )
                            invoice_doc.db_set('custom_uuid' , "Not Submitted" , commit=True  , update_modified=True)
                            invoice_doc.db_set('custom_zatca_status' , "Not Submitted" , commit=True  , update_modified=True)
                            
                           
                            frappe.throw("Error: The request you are sending to Zatca is in incorrect format. Please report to system administrator . Status code:  " + str(response.status_code) + "<br><br> " + response.text )            
                        
                        
                        if response.status_code  in (401,403,407,451 ):
                            invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number  )
                            invoice_doc.db_set('custom_uuid' , "Not Submitted" , commit=True  , update_modified=True)
                            invoice_doc.db_set('custom_zatca_status' , "Not Submitted" , commit=True  , update_modified=True)

                           
                            frappe.throw("Error: Zatca Authentication failed. Your access token may be expired or not valid. Please contact your system administrator. Status code:  " + str(response.status_code) + "<br><br> " + response.text)            
                        
                        if response.status_code not in (200, 202):
                            invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number  )
                            invoice_doc.db_set('custom_uuid' , "Not Submitted" , commit=True  , update_modified=True)
                            invoice_doc.db_set('custom_zatca_status' , "Not Submitted" , commit=True  , update_modified=True)

                            
                          
                          
                            
                            frappe.throw("Error: Zatca server busy or not responding. Try after sometime or contact your system administrator. Status code:  " + str(response.status_code))
                        
                        if response.status_code  in (200, 202):
                                if response.status_code == 202:
                                    msg = "CLEARED WITH WARNIGS: <br> <br> Please copy the below message and send it to your system administrator to fix this warnings before next submission <br>  <br><br> "
                                
                                if response.status_code == 200:
                                    msg = "SUCCESS: <br>   <br><br> "
                                
                                msg = msg + "Status Code: " + str(response.status_code) + "<br><br> "
                                msg = msg + "Zatca Response: " + response.text + "<br><br> "
                                frappe.msgprint(msg)
                                settings.pih = hash_value
                                settings.save(ignore_permissions=True)
                                
                                invoice_doc = frappe.get_doc('Sales Invoice' , invoice_number )
                                invoice_doc.db_set('custom_uuid' , uuid1 , commit=True  , update_modified=True)
                                invoice_doc.db_set('custom_zatca_status' , "CLEARED" , commit=True  , update_modified=True)
                                
                               
                                
                                data=json.loads(response.text)
                                base64_xml = data["clearedInvoice"] 
                                xml_cleared= base64.b64decode(base64_xml).decode('utf-8')
                                file = frappe.get_doc({                       #attaching the cleared xml
                                    "doctype": "File",
                                    "file_name": "Cleared xml file" + sales_invoice_doc.name,
                                    "attached_to_doctype": sales_invoice_doc.doctype,
                                    "attached_to_name": sales_invoice_doc.name,
                                    "content": xml_cleared
                                    
                                })
                                file.save(ignore_permissions=True)
                                # frappe.msgprint(xml_cleared)
                                success_Log(response.text,uuid1, invoice_number)
                                return xml_cleared
                        else:
                                error_Log()
                            
                    except Exception as e:
                        frappe.throw("error in clearance api:  " + str(e) )

def qrcode_From_Clearedxml(xml_cleared):
                    try:
                        # frappe.msgprint("QR code from cleared xml" + str(xml_cleared))
                        root = ET.fromstring(xml_cleared)
                        qr_element = root.find(".//cac:AdditionalDocumentReference[cbc:ID='QR']/cac:Attachment/cbc:EmbeddedDocumentBinaryObject", namespaces={'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2', 'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'})
                        qr_code_text = qr_element.text
                        return qr_code_text
                    except Exception as e:
                        frappe.throw("error in qrcode from cleared xml:  " + str(e) )

def attach_QR_Image_For_Clearance(xml_cleared,sales_invoice_doc):
                    try:
                        # frappe.throw(xml_cleared)
                        qr_code_text=qrcode_From_Clearedxml(xml_cleared)
                        # frappe.throw("qr_code_text: " + str(qr_code_text))
                        qr = pyqrcode.create(qr_code_text)
                        temp_file_path = "qr_code.png"
                        qr_image=qr.png(temp_file_path, scale=5)
                        file = frappe.get_doc({
                            "doctype": "File",
                            "file_name": f"QR_image_{sales_invoice_doc.name}.png",
                            "attached_to_doctype": sales_invoice_doc.doctype,
                            "attached_to_name": sales_invoice_doc.name,
                            "content": open(temp_file_path, "rb").read()
                           
                        })
                        file.save(ignore_permissions=True)
                    except Exception as e:
                        frappe.throw("error in qrcode from cleared xml:  " + str(e) )


@frappe.whitelist(allow_guest=True) 
def zatca_Call(invoice_number, compliance_type="0"):
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
                            qr_code_value=generate_qr_code(signed_xmlfile_name,sales_invoice_doc,path_string)
                            hash_value =generate_hash(signed_xmlfile_name,path_string)
                            # validate_invoice(signed_xmlfile_name,path_string)
                            # frappe.msgprint("validated and stopped it here")
                            # result,clearance_status=send_invoice_for_clearance_normal(uuid1,signed_xmlfile_name,hash_value)
                            
                            if compliance_type == "0":
                                if customer_doc.custom_b2c == 1:
                                    reporting_API(uuid1, hash_value, signed_xmlfile_name,invoice_number,sales_invoice_doc)
                                    attach_QR_Image_For_Reporting(qr_code_value,sales_invoice_doc)
                                else:
                                    
                                    xml_cleared=clearance_API(uuid1, hash_value, signed_xmlfile_name,invoice_number,sales_invoice_doc)
                                    attach_QR_Image_For_Clearance(xml_cleared,sales_invoice_doc)
                            else:  # if it a compliance test
                                # frappe.msgprint("Compliance test")
                                compliance_api_call(uuid1, hash_value, signed_xmlfile_name)
                    except:       
                            frappe.log_error(title='Zatca invoice call failed', message=frappe.get_traceback())
                            
@frappe.whitelist(allow_guest=True) 
def zatca_Call_compliance(invoice_number, compliance_type="0"):
                    # 0 is default. Not for compliance test. But normal reporting or clearance call.
                    # 1 is for compliance test. Simplified invoice
                    # 2 is for compliance test. Standard invoice
                    # 3 is for compliance test. Simplified Credit Note
                    # 4 is for compliance test. Standard Credit Note
                    # 5 is for compliance test. Simplified Debit Note
                    # 6 is for compliance test. Standard Debit Note
                    settings = frappe.get_doc('Zatca setting')
                    
                    if settings.validation_type == "Simplified Invoice":
                        compliance_type="1"
                    elif settings.validation_type == "Standard Invoice":
                        compliance_type="2"
                    elif settings.validation_type == "Simplified Credit Note":
                        compliance_type="3"
                    elif settings.validation_type == "Standard Credit Note":
                        compliance_type="4"
                    elif settings.validation_type == "Simplified Debit Note":
                        compliance_type="5"
                    elif settings.validation_type == "Standard Debit Note":
                        compliance_type="6"
                    
                    # frappe.throw("Compliance Type: " + compliance_type )
                    try:    
                            # create_compliance_x509()
                            # frappe.throw("Created compliance x509 certificate")
                            
                            if not frappe.db.exists("Sales Invoice", invoice_number):
                                frappe.throw("Invoice Number is NOT Valid:  " + str(invoice_number))
                            
                            
                            invoice= xml_tags()
                            invoice,uuid1,sales_invoice_doc=salesinvoice_data(invoice,invoice_number)
                            
                            customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                            
                            
                            invoice = invoice_Typecode_Compliance(invoice, compliance_type)
                            
                            invoice=doc_Reference_compliance(invoice,sales_invoice_doc,invoice_number,compliance_type)
                            invoice=additional_Reference(invoice)
                            invoice=company_Data(invoice,sales_invoice_doc)
                            invoice=customer_Data(invoice,sales_invoice_doc)
                            invoice=delivery_And_PaymentMeans_for_Compliance(invoice,sales_invoice_doc,compliance_type) 
                            invoice=tax_Data(invoice,sales_invoice_doc)
                            invoice=item_data(invoice,sales_invoice_doc)
                            pretty_xml_string=xml_structuring(invoice,sales_invoice_doc)
                            signed_xmlfile_name,path_string=sign_invoice()
                            qr_code_value=generate_qr_code(signed_xmlfile_name,sales_invoice_doc,path_string)
                            hash_value =generate_hash(signed_xmlfile_name,path_string)
                            # validate_invoice(signed_xmlfile_name,path_string)
                            # frappe.msgprint("validated and stopped it here")
                            # result,clearance_status=send_invoice_for_clearance_normal(uuid1,signed_xmlfile_name,hash_value)
                            
                                # frappe.msgprint("Compliance test")
                            compliance_api_call(uuid1, hash_value, signed_xmlfile_name)
                    except:       
                            frappe.log_error(title='Zatca invoice call failed', message=frappe.get_traceback())



                
@frappe.whitelist(allow_guest=True)                  
def zatca_Background(invoice_number):
                    
                    try:
                        # sales_invoice_doc = doc
                        # invoice_number = sales_invoice_doc.name
                        settings = frappe.get_doc('Zatca setting')
                        
                        if settings.zatca_invoice_enabled != 1:
                            frappe.throw("Zatca Invoice is not enabled in Zatca Settings, Please contact your system administrator")
                        
                        if not frappe.db.exists("Sales Invoice", invoice_number):
                                frappe.throw("Please save and submit the invoice before sending to Zatca:  " + str(invoice_number))
                                
                        sales_invoice_doc= frappe.get_doc("Sales Invoice",invoice_number )
            
                        if sales_invoice_doc.docstatus in [0,2]:
                            frappe.throw("Please submit the invoice before sending to Zatca:  " + str(invoice_number))
                            
                        if sales_invoice_doc.custom_zatca_status == "REPORTED" or sales_invoice_doc.custom_zatca_status == "CLEARED":
                            frappe.throw("Already submitted to Zakat and Tax Authority")
                        
                        zatca_Call(invoice_number,0)
                        
                    except Exception as e:
                        frappe.throw("Error in background call:  " + str(e) )
                    
# #                     # frappe.enqueue(
#                     #         zatca_Call,
#                     #         queue="short",
#                     #         timeout=200,
#                     #         invoice_number=invoice_number)
#                     # frappe.msgprint("queued")



@frappe.whitelist(allow_guest=True)          
def zatca_Background_on_submit(doc, method=None):              
# def zatca_Background(invoice_number):
                    
                    try:
                        sales_invoice_doc = doc
                        invoice_number = sales_invoice_doc.name
                        settings = frappe.get_doc('Zatca setting')
                        
                        if settings.zatca_invoice_enabled != 1:
                            frappe.throw("Zatca Invoice is not enabled in Zatca Settings, Please contact your system administrator")
                        
                        if not frappe.db.exists("Sales Invoice", invoice_number):
                                frappe.throw("Please save and submit the invoice before sending to Zatca:  " + str(invoice_number))
                                
                        sales_invoice_doc= frappe.get_doc("Sales Invoice",invoice_number )
            
                        if sales_invoice_doc.docstatus in [0,2]:
                            frappe.throw("Please submit the invoice before sending to Zatca:  " + str(invoice_number))
                            
                        if sales_invoice_doc.custom_zatca_status == "REPORTED" or sales_invoice_doc.custom_zatca_status == "CLEARED":
                            frappe.throw("Already submitted to Zakat and Tax Authority")
                        
                        zatca_Call(invoice_number,0)
                        
                    except Exception as e:
                        frappe.throw("Error in background call:  " + str(e) )
                    
# #                     # frappe.enqueue(
#                     #         zatca_Call,
#                     #         queue="short",
#                     #         timeout=200,
#                     #         invoice_number=invoice_number)
#                     # frappe.msgprint("queued")
