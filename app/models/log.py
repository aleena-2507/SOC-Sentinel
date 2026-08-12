from datetime import datetime

from app.extensions import db


class Log(db.Model):

    __tablename__ = "logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    source = db.Column(
        db.String(100),
        nullable=False
    )

    level = db.Column(
        db.String(20),
        nullable=False
    )

    message = db.Column(
        db.Text,
        nullable=False
    )

    ip_address = db.Column(
        db.String(45),
        nullable=True
    )

    username = db.Column(
        db.String(100),
        nullable=True
    )

    def __repr__(self):
        return f"<Log {self.id}: {self.level}>"