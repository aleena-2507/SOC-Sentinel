from datetime import datetime

from app.extensions import db


class Alert(db.Model):

    __tablename__ = "alerts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="Medium"
    )

    source = db.Column(
        db.String(100),
        nullable=True
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="New"
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    mitre_technique = db.Column(
        db.String(50),
        nullable=True
    )

    def __repr__(self):
        return f"<Alert {self.id}: {self.title}>"