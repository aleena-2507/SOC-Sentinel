from app.extensions import db
from app.models.log import Log
from app.models.alert import Alert
from app.models.detection_rule import DetectionRule


def run_detection():

    rules = DetectionRule.query.filter_by(
        enabled=True
    ).all()

    logs = Log.query.order_by(
        Log.timestamp.asc()
    ).all()

    generated = 0

    for log in logs:

        message = (
            log.message or ""
        ).lower()

        for rule in rules:

            keyword = (
                rule.keyword or ""
            ).lower()

            # Check keyword
            if keyword not in message:
                continue

            # Check source if the rule specifies one
            if rule.source:

                if log.source.lower() != rule.source.lower():
                    continue

            # Prevent duplicate alerts for the same
            # detected event.
            existing = Alert.query.filter_by(
                title=rule.name,
                source=log.source,
                timestamp=log.timestamp
            ).first()

            if existing:
                continue

            alert = Alert(
                title=rule.name,

                description=(
                    f"{rule.description} "
                    f"Detected from log: {log.message}"
                ),

                severity=rule.severity,

                source=log.source,

                status="New",

                timestamp=log.timestamp,

                mitre_technique=rule.mitre_technique
            )

            db.session.add(alert)

            generated += 1

    db.session.commit()

    return generated