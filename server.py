from fastapi import FastAPI
import database
import cifrari
import re
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import datetime
import textwrap
from pydantic import BaseModel



Chiavi = database.Chiavi()
app = FastAPI()

class MESSAGGIO_ARRIVO(BaseModel):
    cifratoAES: str
    ChiaveCifrata: str
    
class AUTENTICAZIONE(BaseModel):
    cifratoAES: str
    ChiaveCifrata: str
    API_KEY: str


@app.post("/registrazione")
async def registrazione(mess : MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
        Prefisso,Numero,password = dati.split(" ")
        messaggio = Chiavi.registra(Prefisso,Numero, password)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
        return {"risposta": "Errore"}



@app.post("/login")
async def login(login : MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(login.ChiaveCifrata))
        dati = cifrari.decifra(login.cifratoAES, chiaveAES)
        dati = re.sub("\s\s+", " ", dati)
        Prefisso,Numero,password = dati.split(" ")
        messaggio = Chiavi.login(Prefisso,Numero, password)
        print(messaggio)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
            return {"risposta": "Errore"}




@app.post("/cerca_numero")
async def cerca(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        numero = cifrari.decifra(mess.cifratoAES, chiaveAES)
        messaggio = Chiavi.Cerca(numero)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta" : messaggio}
    except Exception as e:
        return {"risposta": "Errore"}




@app.post("/reg_id")
async def reg_id(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
        Prefisso,Numero,firebaseid = dati.split(" ")
        messaggio = Chiavi.registra_id(Prefisso,Numero, firebaseid)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta" : messaggio} 
    except Exception as e:
        return {"risposta": "Errore"}



@app.post("/chiave")
async def chiave(mess: AUTENTICAZIONE):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
        id1,id2 = dati.split(" ")
        messaggio = Chiavi.salvachiave(id1,id2, mess.API_KEY)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
        return {"risposta": "Errore"}




@app.post("/cerca_id")
async def cerca_id(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        id = cifrari.decifra(mess.cifratoAES, chiaveAES)
        messaggio = Chiavi.Cerca_id(id)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
        return {"risposta": "Errore"}


