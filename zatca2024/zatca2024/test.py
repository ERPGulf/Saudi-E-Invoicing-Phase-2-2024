from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

#  same value in cert.pem   - add begin and end lines  ( probably base64 of binary security token, dont remember. you check and confirm.  )
cert_base64 = """
-----BEGIN CERTIFICATE-----
MIID3jCCA4SgAwIBAgITEQAAOAPF90Ajs/xcXwABAAA4AzAKBggqhkjOPQQDAjBiMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNnb3YxFzAVBgoJkiaJk/IsZAEZFgdleHRnYXp0MRswGQYDVQQDExJQUlpFSU5WT0lDRVNDQTQtQ0EwHhcNMjQwMTExMDkxOTMwWhcNMjkwMTA5MDkxOTMwWjB1MQswCQYDVQQGEwJTQTEmMCQGA1UEChMdTWF4aW11bSBTcGVlZCBUZWNoIFN1cHBseSBMVEQxFjAUBgNVBAsTDVJpeWFkaCBCcmFuY2gxJjAkBgNVBAMTHVRTVC04ODY0MzExNDUtMzk5OTk5OTk5OTAwMDAzMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEoWCKa0Sa9FIErTOv0uAkC1VIKXxU9nPpx2vlf4yhMejy8c02XJblDq7tPydo8mq0ahOMmNo8gwni7Xt1KT9UeKOCAgcwggIDMIGtBgNVHREEgaUwgaKkgZ8wgZwxOzA5BgNVBAQMMjEtVFNUfDItVFNUfDMtZWQyMmYxZDgtZTZhMi0xMTE4LTliNTgtZDlhOGYxMWU0NDVmMR8wHQYKCZImiZPyLGQBAQwPMzk5OTk5OTk5OTAwMDAzMQ0wCwYDVQQMDAQxMTAwMREwDwYDVQQaDAhSUlJEMjkyOTEaMBgGA1UEDwwRU3VwcGx5IGFjdGl2aXRpZXMwHQYDVR0OBBYEFEX+YvmmtnYoDf9BGbKo7ocTKYK1MB8GA1UdIwQYMBaAFJvKqqLtmqwskIFzVvpP2PxT+9NnMHsGCCsGAQUFBwEBBG8wbTBrBggrBgEFBQcwAoZfaHR0cDovL2FpYTQuemF0Y2EuZ292LnNhL0NlcnRFbnJvbGwvUFJaRUludm9pY2VTQ0E0LmV4dGdhenQuZ292LmxvY2FsX1BSWkVJTlZPSUNFU0NBNC1DQSgxKS5jcnQwDgYDVR0PAQH/BAQDAgeAMDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIGGqB2E0PsShu2dJIfO+xnTwFVmh/qlZYXZhD4CAWQCARIwHQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMCMCcGCSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwMwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIhALE/ichmnWXCUKUbca3yci8oqwaLvFdHVjQrveI9uqAbAiA9hC4M8jgMBADPSzmd2uiPJA6gKR3LE03U75eqbC/rXA==
-----END CERTIFICATE-----
"""

cert = x509.load_pem_x509_certificate(cert_base64.encode(), default_backend())

public_key = cert.public_key()

public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

print("Public Key ",public_key_pem)  #  - This is the public-key used in QR code. remove begin and end string

print("            ")
import binascii

base64_encoded_public_key = base64.b64encode(public_key_pem).decode('utf-8')

print("Base64 encoded " ,base64_encoded_public_key)
with open('new_p.pem', 'wb') as f:
      f.write(public_key_pem)
with open("new_p.pem", 'r') as file:
        lines = file.readlines()
        key_data = ''.join(lines[1:-1])  
key_data = key_data.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')
key_data = key_data.replace(' ', '').replace('\n', '')
# return key_data
byte_data = base64.b64decode(key_data)
hex_data = binascii.hexlify(byte_data).decode('utf-8')
print(hex_data)
chunks = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]

# Initialize variables for tag, length, and value
tag = length = value = ''

# Iterate through the chunks to format them into TLV format
tlv_data = ''
for i, chunk in enumerate(chunks):
    if i % 3 == 0:
        tag = chunk
    elif i % 3 == 1:
        length = chunk
    else:
        value += chunk
        # If this is the last chunk for this TLV, add it to the output
        if i % 3 == 2:
            tlv_data += f"{tag} {length} {value} "

            # Reset variables for the next TLV
            tag = length = value = ''

# print(tlv_data.strip())
tlv_parts = tlv_data.split()
binary_data = b''

for i in range(0, len(tlv_parts), 3):
    tag = int(tlv_parts[i], 16)
    length = int(tlv_parts[i + 1], 16)
    value = bytes.fromhex(tlv_parts[i + 2])
    binary_data += bytes([tag]) + bytes([length]) + value

base64_encoded1 = base64.b64encode(binary_data).decode('utf-8')
print(base64_encoded1)
# return base64_encoded1