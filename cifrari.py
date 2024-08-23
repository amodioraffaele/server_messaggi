from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from dotenv import load_dotenv
import os
from Cryptodome.PublicKey import RSA



def decifra(dati, chiave):
    cifrario = AES.new(chiave, AES.MODE_ECB)
    dat = cifrario.decrypt(b64decode(dati))
    dat = unpad(dat, 16)
    print("CHIARO STRINGA: " + dat.decode(encoding="latin-1"))
    return dat.decode(encoding="latin-1")

def cifraAES(dati, chiave):
    cifrario = AES.new(chiave, AES.MODE_ECB)
    dat = cifrario.decrypt(pad(dati, 16))
    return dat.decode(encoding="latin-1")

def decifraRSA(cifrato):
    chiave = """-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCcZxohMIF3nx28
PMlrYfCvRAAgQQmmImhpr4c9fzYyd9g6799FMnJKiMBwjnBwvXQdP0O7klXd1dJj
HCM7dA9XyVOr94nLrqVkeFQ61xXOFwFnWzzUsf4D6eYfqXYK/LNcrxMe4Hubt0zP
w5sPJIdBzbj890VOmQcYjLB5IeL2jDVHvVzOSNG2CwUxu9VXBx60f/dE8qZts7rn
BLp5Ndw3UHaR4L3HS/jygOb2nr5seE9P/T0UU3KRkopv6ffxwycFXZLz91o8GnO5
/armE07YR7ED2H/CZbakJbEWrXdNe9SWrodTpOmdX2rNjVvS9SlIixerd3518Jh9
XZH7+purAgMBAAECggEAPoi8ulN2GHmOvpJBaIV+4dza/gpzDLGKNOOBO9XuugwP
8TSyfSzX5LQ72WUiUPl3ATCn6MnwOiPBnG4GKkHT1qJBKatuNXmtWHgCGYqhBcdO
AODKeDJ4oWD2aWdssqTqJB8+EmToF1EZTaLkjw/oYqeaFM7bL7tgynCKKMyjPjcd
0VNtZnRm5Cxh7ct4GA9YP4mWXgfIOtpzNke0FGMdQdYdB/G3l8ZE4kZBjkHHeSOO
bAG0cEWasR0SgJoTgtFHnxAgnpamiPcAC2Xq/KuaIhSeIxZJ5GdX+Esgk9IBb/35
+GfAFQb41EH4GFfDzJCDjIFPbdG+XY8t2jX8UrZglQKBgQDUrnLj0/RVRBSG6V61
wzT/h+5WehcylpdTdtvYhY0ABfXDradUddQJ1BrvXgdtofNL7q/EAv84o96LLn1Q
H5evgzLZeFZER64YhlWRL5g15CxoN/m9a/30z80puHBDAUBAwBoXV4UXO/yAq/Dh
xMQG6tkiErUdatzmUe76R81c3wKBgQC8QjEWteoyxC6PfsCq85V38pAdXpLNdM+9
nUHk9wD7NkeL7y71HN6uKN/7gjmY/WjbOx8XhIDhBbHj/dZDx8lieJIUx063YNFO
bI0AHYkYL1F1xOUz00E1CsRUKmt7FEXWBiuzniEuYlsFqML2jB7BoFmoHK/9n7yo
oDDtDgROtQKBgQCEP7XRVYspOhxJh/QMskXSX4Qk4eZq3planR43lVQIH6yi8OiL
7HjdY7ccASw9T+cp4FILYJGzdrJ7eX0SxZJc4QhNkjaSXsAzH9U1YpMTb77tT2FM
GEriYBUDTF0CTVTW7p1KxnFL8VEh8cjnmqMKah56wYc9s6WI0on3t45LoQKBgGu+
ZmHdE4CijxNJM/OjHTRc+uYULmiwJgUbb48fXsxnsGMCLRnTwA5lDmvfiB9rSQvP
tme7Shd/LuSRboO0YCmfX9vMhdyl6KS9s6URQlk5G6IPYi5bBcLZuquA66qxW5a2
SWSvZ8YoPHfsskhwwVmH8Egqwv6g4VSQ+e9ySjzRAoGAdzy6jq6NxVgS1mHavChs
GbnIgWo2J7Gs7plxBpCubmqwxF5HcRRRAaEKIUJ1BY092u5hjc9glJisomWmjdGe
j7HcbWfbQ02npeKjKjb31dIA2N2/4mPaXiPPcAqL9CPS/iOnISQ0e9avs+koTptI
pe+kRD4J/76buZsa5m4vCG4=
-----END RSA PRIVATE KEY-----"""
    private_key = RSA.import_key(chiave)
    cipher = PKCS1_v1_5.new(private_key)
    PlainText = cipher.decrypt(cifrato, "errore")
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