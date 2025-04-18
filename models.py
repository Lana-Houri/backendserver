from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class CellData(db.Model):
    __tablename__ = 'cell_data'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String, nullable=False)
    operator = db.Column(db.String)
    signal_power = db.Column(db.Integer)
    snr = db.Column(db.Float)
    network_type = db.Column(db.String)
    band = db.Column(db.String)
    cell_id = db.Column(db.String)
    device_ip = db.Column(db.String)
    device_mac = db.Column(db.String)
