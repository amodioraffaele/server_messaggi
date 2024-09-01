from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from dotenv import load_dotenv
import os
from Cryptodome.PublicKey import RSA
from cryptography.hazmat.primitives import serialization


def decifra(dati, chiave):
    cifrario = AES.new(chiave, AES.MODE_ECB)
    dat = cifrario.decrypt(b64decode(dati))
    dat = unpad(dat, 16)
    print("CHIARO STRINGA: " + dat.decode(encoding="latin-1"))
    return dat.decode(encoding="latin-1")

def cifraAES(dati, chiave):
    cifrario = AES.new(chiave, AES.MODE_ECB)
    dat = cifrario.encrypt(pad(dati.encode(), 16))
    return b64encode(dat)



def decifraRSA(cifrato):
    with open("server\chiave-priv.pem", "rb") as f:
        chiave = serialization.load_pem_private_key(f.read(), None)
    cifrario = PKCS1_v1_5.new(chiave)
    PlainText = cifrario.decrypt(cifrato, "errore")
    return PlainText

def cifraRSA(dati):
    chiave = """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnGcaITCBd58dvDzJa2Hw
r0QAIEEJpiJoaa+HPX82MnfYOu/fRTJySojAcI5wcL10HT9Du5JV3dXSYxwjO3QP
V8lTq/eJy66lZHhUOtcVzhcBZ1s81LH+A+nmH6l2CvyzXK8THuB7m7dMz8ObDySH
Qc24/PdFTpkHGIyweSHi9ow1R71czkjRtgsFMbvVVwcetH/3RPKmbbO65wS6eTXc
N1B2keC9x0v48oDm9p6+bHhPT/09FFNykZKKb+n38cMnBV2S8/daPBpzuf2q5hNO
2EexA9h/wmW2pCWxFq13TXvUlq6HU6TpnV9qzY1b0vUpSIsXq3d+dfCYfV2R+/qb
qwIDAQAB
-----END RSA PUBLIC KEY-----
"""
    public_key = RSA.import_key(chiave)
    cifrario = PKCS1_v1_5.new(public_key)
    cifrato = cifrario.encrypt(dati.encode())
    return cifrato.decode(encoding="latin-1")

def env(Nome):
    load_dotenv()
    return os.getenv(Nome)
