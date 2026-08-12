from datetime import datetime

from app.extensions import db


class DetectionRule(db.Model):

    __tablename__ = "detection_rules"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(200),
        nullable=False,
        unique=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    keyword = db.Column(
        db.String(200),
        nullable=False
    )

    source = db.Column(
        db.String(100),
        nullable=True
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="Medium"
    )

    mitre_technique = db.Column(
        db.String(50),
        nullable=True
    )

    enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    def __repr__(self):
        return f"<DetectionRule {self.id}: {self.name}>"