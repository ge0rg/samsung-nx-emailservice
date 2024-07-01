from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64decode
from urllib.parse import unquote
import xml.etree.ElementTree as ET

def decrypt_string(key, s):
    d = Cipher(algorithms.AES(key[0:16]), modes.CBC(key[16:])).decryptor()
    dec = d.update(s)
    return dec.decode('utf-8').rstrip('\0')

def extract_credentials(xml):
    x_csk = xml.find("CryptSessionKey")
    x_user = xml.find("UserName")
    x_pw = xml.find("Password")
    x_oauth = xml.find("OAuth")
    x_appkey = xml.find("ApplicationKey")

    # HMX-QF30: TLS encrypted, no credential encryption
    if not 'Value' in x_csk.attrib:
        creds = {}
        creds['user'] = unquote(x_user.attrib['Value'])
        creds['pw'] = unquote(x_pw.attrib['Value'])
        creds['applicationkey'] = x_appkey.attrib['Value']
        return creds

    key = b64decode(x_csk.attrib['Value'])
    creds = { 'key': key, 'applicationkey': x_appkey.attrib['Value'] }

    if x_user is not None and x_pw is not None:
        enc_user = b64decode(unquote(x_user.attrib['Value']))
        enc_pw = b64decode(unquote(x_pw.attrib['Value']))
        creds['user'] = decrypt_string(key, enc_user)
        creds['pw'] = decrypt_string(key, enc_pw)
    if x_oauth is not None:
        creds['oauth'] = x_oauth.attrib['Version']

    return creds

def decrypt_file(fn):
    key, user, pw = decrypt_credentials(ET.parse(fn).getroot())
    print('User:', user, 'Password:', pw)

def extract_photo(xml):
    photo = xml.find("Photo")
    sessionkey = xml.attrib["SessionKey"]
    albumname = photo.find("Album").attrib["Name"]
    filename = photo.find("File").attrib["Name"]
    content = photo.find("Content").text
    return {
            'sessionkey': sessionkey,
            'album': albumname,
            'filename': filename,
            'content': content,
            }

def extract_video(xml):
    photo = xml.find("Video")
    sessionkey = xml.attrib["SessionKey"]
    category = photo.find("Category")
    albumname = None
    owner = None
    if category:
        albumname = category.attrib["Name"]
        owner = category.attrib["OwnerID"]
    filename = photo.find("File").attrib["Name"]
    content = photo.find("Content").text
    return {
            'sessionkey': sessionkey,
            'album': albumname,
            'owner': owner,
            'filename': filename,
            'content': content,
            }

