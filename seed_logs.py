from datetime import datetime, timedelta

from app.app import create_app
from app.extensions import db
from app.models.log import Log


app = create_app()


sample_logs = [

    {
        "source": "Windows Authentication",
        "level": "ERROR",
        "message": "Failed login attempt for user admin",
        "ip_address": "192.168.1.25",
        "username": "admin"
    },

    {
        "source": "Windows Authentication",
        "level": "WARNING",
        "message": "Multiple failed authentication attempts detected",
        "ip_address": "192.168.1.25",
        "username": "admin"
    },

    {
        "source": "Firewall",
        "level": "WARNING",
        "message": "Connection attempt to restricted port 3389",
        "ip_address": "185.22.14.91",
        "username": None
    },

    {
        "source": "Network Monitor",
        "level": "ERROR",
        "message": "Port scan activity detected across multiple ports",
        "ip_address": "185.22.14.91",
        "username": None
    },

    {
        "source": "Web Server",
        "level": "INFO",
        "message": "GET request received for /login",
        "ip_address": "10.0.0.15",
        "username": None
    },

    {
        "source": "Web Server",
        "level": "ERROR",
        "message": "HTTP 401 unauthorized request",
        "ip_address": "10.0.0.15",
        "username": "unknown"
    },

    {
        "source": "Endpoint Security",
        "level": "CRITICAL",
        "message": "Suspicious executable detected",
        "ip_address": "192.168.1.44",
        "username": "user1"
    },

    {
        "source": "Network Monitor",
        "level": "WARNING",
        "message": "Unusual outbound traffic detected",
        "ip_address": "192.168.1.44",
        "username": "user1"
    },

    {
        "source": "Firewall",
        "level": "INFO",
        "message": "Allowed outbound connection",
        "ip_address": "192.168.1.20",
        "username": "user2"
    },

    {
        "source": "Windows Authentication",
        "level": "INFO",
        "message": "Successful user login",
        "ip_address": "192.168.1.20",
        "username": "user2"
    },

    {
        "source": "Web Server",
        "level": "WARNING",
        "message": "Repeated requests from the same source",
        "ip_address": "45.77.21.12",
        "username": None
    },

    {
        "source": "Endpoint Security",
        "level": "ERROR",
        "message": "Malicious process behavior detected",
        "ip_address": "192.168.1.55",
        "username": "user3"
    },

    {
        "source": "Firewall",
        "level": "CRITICAL",
        "message": "Blocked connection from known suspicious source",
        "ip_address": "91.214.124.31",
        "username": None
    },

    {
        "source": "Network Monitor",
        "level": "INFO",
        "message": "Normal network traffic observed",
        "ip_address": "192.168.1.10",
        "username": None
    },

    {
        "source": "Windows Authentication",
        "level": "ERROR",
        "message": "Account authentication failure",
        "ip_address": "192.168.1.88",
        "username": "administrator"
    }
]


with app.app_context():

    existing_count = Log.query.count()

    if existing_count > 0:

        print(
            f"Logs already exist: {existing_count}"
        )

    else:

        base_time = datetime.utcnow()

        for index, data in enumerate(sample_logs):

            log = Log(
                timestamp=base_time - timedelta(
                    minutes=index * 7
                ),
                source=data["source"],
                level=data["level"],
                message=data["message"],
                ip_address=data["ip_address"],
                username=data["username"]
            )

            db.session.add(log)

        db.session.commit()

        print(
            f"{len(sample_logs)} sample logs added successfully."
        )