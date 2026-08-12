from app.app import create_app
from app.extensions import db
from app.models.alert import Alert


app = create_app()

with app.app_context():

    alerts = [
        Alert(
            title="Multiple Failed Login Attempts",
            description="Multiple unsuccessful authentication attempts detected from the same source.",
            severity="Critical",
            source="Windows Authentication",
            status="New",
            mitre_technique="T1110"
        ),

        Alert(
            title="Port Scan Detected",
            description="Multiple connection attempts to different ports were detected.",
            severity="High",
            source="Network Monitoring",
            status="New",
            mitre_technique="T1046"
        ),

        Alert(
            title="Unusual Outbound Traffic",
            description="Unusual outbound network traffic was detected from an endpoint.",
            severity="Medium",
            source="Network Monitoring",
            status="New",
            mitre_technique="T1071"
        )
    ]

    db.session.add_all(alerts)
    db.session.commit()

    print("3 sample alerts added successfully.")