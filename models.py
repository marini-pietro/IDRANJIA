from flask_sqlalchemy import SQLAlchemy

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
    accessibilita = db.Column(db.String, nullable=False)
    email_ins = db.Column(db.String, nullable=False)

class User(db.Model):
    __tablename__ = "utenti"
    email = db.Column(db.String, primary_key=True)
    password = db.Column(db.String, nullable=False)
    comune = db.Column(db.String, nullable=False)

class Operator(db.Model):
    __tablename__ = "operatori"
    id = db.Column(db.Integer, primary_key=True)
    CF = db.Column(db.String, unique=True, nullable=False)
    nome = db.Column(db.String, nullable=False)
    cognome = db.Column(db.String, nullable=False)

class Photo(db.Model):
    __tablename__ = "foto"
    id = db.Column(db.Integer, primary_key=True)
    id_idrante = db.Column(db.Integer, db.ForeignKey('idranti.id'), nullable=False)
    posizione = db.Column(db.String, nullable=False)
    data = db.Column(db.String, nullable=False)

class Control(db.Model):
    __tablename__ = "controlli"
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String, nullable=False)
    esito = db.Column(db.Boolean, nullable=False)
    data = db.Column(db.Date, nullable=False)
    id_idrante = db.Column(db.Integer, db.ForeignKey('idranti.id'), nullable=False)

# Add other models as needed, following the same pattern.
