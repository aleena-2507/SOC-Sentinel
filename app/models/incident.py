from datetime import datetime

from app.extensions import db


class Incident(db.Model):

    __tablename__ = "incidents"

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

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Open"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    alert_id = db.Column(
        db.Integer,
        db.ForeignKey("alerts.id"),
        nullable=True
    )

    alert = db.relationship(
        "Alert",
        backref=db.backref("incident", uselist=False)
    )

    def __repr__(self):
        return f"<Incident {self.id}: {self.title}>"