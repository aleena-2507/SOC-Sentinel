from app.app import create_app
from app.extensions import db
from app.models.detection_rule import DetectionRule


app = create_app()


sample_rules = [

    {
        "name": "Failed Login Detection",
        "description": "Detects failed authentication attempts.",
        "keyword": "failed login",
        "source": "Windows Authentication",
        "severity": "Critical",
        "mitre_technique": "T1110"
    },

    {
        "name": "Port Scan Detection",
        "description": "Detects possible network port scanning activity.",
        "keyword": "port scan",
        "source": "Network Monitor",
        "severity": "High",
        "mitre_technique": "T1046"
    },

    {
        "name": "Unusual Outbound Traffic",
        "description": "Detects unusual outbound network traffic.",
        "keyword": "unusual outbound traffic",
        "source": "Network Monitor",
        "severity": "Medium",
        "mitre_technique": "T1071"
    },

    {
        "name": "Suspicious Executable Detection",
        "description": "Detects suspicious executable or process behavior.",
        "keyword": "suspicious executable",
        "source": "Endpoint Security",
        "severity": "Critical",
        "mitre_technique": "T1204"
    }

]


with app.app_context():

    added = 0

    for data in sample_rules:

        existing = DetectionRule.query.filter_by(
            name=data["name"]
        ).first()

        if existing:
            continue

        rule = DetectionRule(
            name=data["name"],
            description=data["description"],
            keyword=data["keyword"],
            source=data["source"],
            severity=data["severity"],
            mitre_technique=data["mitre_technique"],
            enabled=True
        )

        db.session.add(rule)

        added += 1

    db.session.commit()

    print(
        f"{added} detection rules added successfully."
    )