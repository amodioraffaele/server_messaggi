import mysql.connector
import bcrypt
import random
import uuid
from cifrari import cifraRSA, decifraRSA

class Chiavi():
    def __init__(self):
        self.database = mysql.connector.connect( 
            host="localhost",
            user="root",
            password="",
            database="utenti"
        )
        self.cursor = self.database.cursor(buffered=True) #buffered=True per evitare errore di "Unread result found" -> è dovuto al fetchone che non legge tutti i risultati


    def salvachiave(self, id1, id2):
        print("id1: "+id1)
        print("id2: "+id2)
        query = "SELECT chiave FROM chiavi WHERE (FirebaseID1= %s AND FirebaseID2 = %s) OR (FirebaseID1 = %s AND FirebaseID2 = %s)"
        self.cursor.execute(query, (id1, id2, id2, id1))
        result = self.cursor.fetchone()
        if result == None:
            query = "SELECT id FROM user WHERE FirebaseID = %s OR FirebaseID = %s"
            self.cursor.execute(query, (id1, id2))
            result = self.cursor.fetchall()
            chiave = ""
            if id1 == id2:
                result = (result[0], result[0])
            for i in range(0,16):
                chiave = chiave+ result[0][0][random.choice([0,len(result[0])])] + result[1][0][random.choice([0,len(result[1])])]
            query = "INSERT INTO chiavi (FirebaseID1, FirebaseID2, chiave) VALUES (%s, %s, %s)"
            chiaveCifrata = cifraRSA(chiave)
            self.cursor.execute(query, (id1, id2, chiaveCifrata))
            self.database.commit()
            print(chiave)
            return chiave
        else:
            chiave = decifraRSA(result[0].encode("latin-1"))
            print(chiave)
            return chiave.decode("latin-1")


    def Cerca_id(self, id):
        query = "SELECT Numero FROM user WHERE FirebaseID = %s"
        self.cursor.execute(query, (id,))
        result = self.cursor.fetchone()
        if result == None:
            m = "Id non trovato"
        else:
            m = result[0]
        return m
    
    def Cerca(self, Numero):
        query = "SELECT FirebaseID FROM user WHERE Numero = %s"
        self.cursor.execute(query, (Numero,))
        result = self.cursor.fetchone()
        if result == None or result[0].strip() == "":
            m = "Numero non trovato"
        else:
            m = result[0]
        return m
    
    def registra(self,Prefisso, Numero, password):
        id = uuid.uuid1().hex
        id_esiste = True
        query = "SELECT count(*) FROM user WHERE Numero = %s AND Prefisso = %s"
        self.cursor.execute(query, (Prefisso,Numero))
        n = self.cursor.fetchone()
        if n[0] != 0:
            m = "Numero già registrato"
        else:
            while id_esiste:
                query = "SELECT count(*) FROM user WHERE Prefisso = %s AND id = %s"
                self.cursor.execute(query, (Prefisso,Numero))
                n = self.cursor.fetchone()
                if n[0] == 0:
                    id_esiste = False   
                else:
                    id = uuid.uuid1().hex
            query = "INSERT INTO user (Prefisso, Numero, Password, id) VALUES (%s,%s, %s, %s)"
            self.cursor.execute(query, (Prefisso,Numero, password, id))
            self.database.commit()
            m = "Successo"
        return m
    def login(self,Prefisso, Numero, password):
        query = "SELECT Password, Salt FROM user WHERE Numero = %s AND Prefisso = %s"
        self.cursor.execute(query, (Numero,Prefisso))
        result = self.cursor.fetchall()
        if len(result) == 0:
            m = "Numero non trovato"
        else:
            result = result[0]
            if bcrypt.checkpw(password.encode(), result[0].encode()): #altrimenti .encode() a pass e result        
                        #bcrypt non ha database per salvare password e hash, quando crypta una password mentte prima il salt, così, quando poi deve controllare con checkpw, estrare il salt
                        #hasha la password data con il salt estratto e controlla se è uguale all'hash salvato
                m = "Successo"
            else:
                m = "Password errata"
        return m
    def registra_id(self,prefisso,numero,firebaseid):
        query = "UPDATE user SET FirebaseID = %s WHERE Prefisso = %s AND Numero = %s"
        self.cursor.execute(query, (firebaseid, prefisso, numero))
        self.database.commit()
        return "Successo"