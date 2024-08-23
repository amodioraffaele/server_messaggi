import socket
import database
import cifrari
import re
import ssl
from base64 import b64decode
import certifi



def server():
    host = socket.gethostname()
    print(host)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="public-cert.pem", keyfile="private-key.pem")

# a TCP/IP socket
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind(("192.168.178.22", 21402))
    sk.listen(5)

    Chiavi = database.Chiavi()
    with context.wrap_socket(sk, server_side=True) as ssock:
        try:
            while True:
                cod, indirizzo = ssock.accept()
                while True:
                    ricevuti = cod.recv(4096)
                    if not ricevuti:
                        break
                    ricevuti = ricevuti.decode().strip()
                    messaggio = ""
                    if ricevuti.startswith("chiave: "):
                        chiave = ricevuti.removeprefix("chiave: ")
                        Chiavi.salvachiave(chiave,indirizzo)
                    else:
                        cifratoAES, ChiaveCifrata = ricevuti.split("chiave: ") 
                        chiaveAES = cifrari.decifraRSA(b64decode(ChiaveCifrata))
                        dati = cifrari.decifra(cifratoAES, chiaveAES)
                        if dati.startswith("Reg: "):
                            dati = dati.removeprefix("Reg: ")
                            Prefisso,Numero,password = dati.split(" ")
                            messaggio = Chiavi.registra(Prefisso,Numero, password)
                        elif dati.startswith("Login: "):
                            dati = dati.removeprefix("Login: ").strip()
                            dati = re.sub("\s\s+", " ", dati)
                            print(dati)
                            Prefisso,Numero,password = dati.split(" ")
                            messaggio = Chiavi.login(Prefisso,Numero, password)
                        elif dati.startswith("Cerca: "):
                            Numero = dati.removeprefix("Cerca: ").strip()
                            messaggio = Chiavi.Cerca(Numero)
                        elif dati.startswith("Reg_id: "):
                            dati = dati.removeprefix("Reg_id: ")
                            Prefisso,Numero,firebaseid = dati.split(" ")
                            messaggio = Chiavi.registra_id(Prefisso,Numero, firebaseid)
                        elif dati.startswith("chiave: "):
                            dati = dati.removeprefix("chiave: ").strip()
                            id1,id2 = dati.split(" ")
                            messaggio = Chiavi.salvachiave(id1,id2)
                        elif dati.startswith("Cerca_id: "):
                            id = dati.removeprefix("Cerca_id: ").strip()
                            messaggio = Chiavi.Cerca_id(id)
                        else:
                            messaggio = dati
                        #xmessaggio = cifrari.cifraAES(messaggio, chiaveAES)
                        messaggio = messaggio + "\n"
                        print("risposta:")
                        print(messaggio)
                        cod.send(messaggio.encode())
        except Exception as e:
            print(e)
            server()




    

server()