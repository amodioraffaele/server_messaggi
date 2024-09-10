from fastapi import FastAPI
import database
import cifrari
from base64 import b64decode
from pydantic import BaseModel



Database = database.Database()
app = FastAPI()

class MESSAGGIO_ARRIVO(BaseModel):
    cifratoAES: str
    ChiaveCifrata: str
    


@app.post("/registrazione")
async def registrazione(mess : MESSAGGIO_ARRIVO):
        try:
            chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
            dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
            Prefisso,Numero,password = dati.split(" ")
            if len(Numero) != 10:
                return {"risposta": "Numero non valido"}
            messaggio = Database.registra(Prefisso,Numero, password)
            messaggio = cifrari.cifraAES(messaggio, chiaveAES)
            return {"risposta": messaggio}
        except Exception as e:
            return {"risposta": "Errore"}




@app.post("/login")
async def login(login : MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(login.ChiaveCifrata))
        dati = cifrari.decifra(login.cifratoAES, chiaveAES)
        Prefisso,Numero,password = dati.split(" ")
        if len(Numero) != 10:
            return {"risposta": "Numero non valido"}
        messaggio = Database.login(Prefisso,Numero, password)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
            return {"risposta": "Errore"}




@app.post("/cerca_numero")
async def cerca(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        numero = cifrari.decifra(mess.cifratoAES, chiaveAES)
        if len(numero) != 10:
            return {"risposta": "Numero non valido"}
        messaggio = Database.Cerca(numero)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta" : messaggio}
    except Exception as e:
        return {"risposta": "Errore"}




@app.post("/reg_id")
async def reg_id(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
        Prefisso,Numero,firebaseid, password = dati.split(" ")
        if len(Numero) != 10:
            return {"risposta": "Numero non valido"}
        messaggio = Database.registra_id(Prefisso,Numero, firebaseid,password)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta" : messaggio} 
    except Exception as e:
        return {"risposta": "Errore"}



@app.post("/chiave")
async def chiave(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
        id1,id2, API_KEY = dati.split(" ")
        messaggio = Database.salvachiave(id1,id2, API_KEY)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
        return {"risposta": "Errore"}




@app.post("/cerca_id")
async def cerca_id(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        id = cifrari.decifra(mess.cifratoAES, chiaveAES)
        messaggio = Database.Cerca_id(id)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
        return {"risposta": "Errore"}



@app.post("/cambia_password")
async def cambia_password(mess: MESSAGGIO_ARRIVO):
    try:
        chiaveAES = cifrari.decifraRSA(b64decode(mess.ChiaveCifrata))
        dati = cifrari.decifra(mess.cifratoAES, chiaveAES)
        Numero, password, nuovapassword = dati.split(" ")
        if len(Numero) != 10:
            return {"risposta": "Numero non valido"}
        messaggio = Database.cambia_password(Numero, password, nuovapassword)
        messaggio = cifrari.cifraAES(messaggio, chiaveAES)
        return {"risposta": messaggio}
    except Exception as e:
        return {"risposta": "Errore"}



