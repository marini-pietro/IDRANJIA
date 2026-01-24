from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import ENUM

db = SQLAlchemy()


class Hydrant(db.Model):
    __tablename__ = "idranti"
    id = db.Column(db.Integer, primary_key=True)
    stato = db.Column(db.String, nullable=False)
    latitudine = db.Column(db.Float, nullable=False)
    longitudine = db.Column(db.Float, nullable=False)
    comune = db.Column(db.String, nullable=False)
    via = db.Column(db.String, nullable=False)
    area_geo = db.Column(db.String, nullable=False)
    tipo = db.Column(db.String, nullable=False)
    accessibilità = db.Column(db.String, nullable=False)
    email_ins = db.Column(db.String, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "stato": self.stato,
            "latitudine": self.latitudine,
            "longitudine": self.longitudine,
            "comune": self.comune,
            "via": self.via,
            "area_geo": self.area_geo,
            "tipo": self.tipo,
            "accessibilità": self.accessibilità,
            "email_ins": self.email_ins,
        }

user_role_enum = ENUM('admin', 'operator', 'viewer', name='user_role')

class User(db.Model):
    __tablename__ = "utenti"
    email = db.Column(db.String, primary_key=True)
    comune = db.Column(db.String, nullable=False)
    nome = db.Column(db.String, nullable=False)
    cognome = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    ruolo = db.Column(user_role_enum, nullable=False, default='viewer')
    
    def to_dict(self):
        return {
            "email": self.email,
            "comune": self.comune,
            "nome": self.nome,
            "cognome": self.cognome,
            "password": self.password,
            "ruolo": self.ruolo,
        }


class Operator(db.Model):
    __tablename__ = "operatori"
    CF = db.Column(db.String(16), primary_key=True)
    nome = db.Column(db.String, nullable=False)
    cognome = db.Column(db.String, nullable=False)

    def to_dict(self):
        return {
            "CF": self.CF,
            "nome": self.nome,
            "cognome": self.cognome,
        }


class Photo(db.Model):
    __tablename__ = "foto"
    id_foto = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False)
    id_idrante = db.Column(db.Integer, db.ForeignKey("idranti.id"), nullable=False)
    posizione = db.Column(db.String, nullable=False)

    def to_dict(self):
        return {
            "id_foto": self.id_foto,
            "data": self.data,
            "id_idrante": self.id_idrante,
            "posizione": self.posizione,
        }


class Control(db.Model):
    __tablename__ = "controlli"
    id_controllo = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False)
    tipo = db.Column(db.String, nullable=False)
    esito = db.Column(db.Boolean, nullable=False)
    id_idrante = db.Column(db.Integer, db.ForeignKey("idranti.id"), nullable=False)

    def to_dict(self):
        return {
            "id_controllo": self.id_controllo,
            "data": self.data,
            "tipo": self.tipo,
            "esito": self.esito,
            "id_idrante": self.id_idrante,
        }
