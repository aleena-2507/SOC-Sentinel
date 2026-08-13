from io import BytesIO
from re import search

from flask import Flask, redirect, render_template, request, url_for
import os
from sqlalchemy import Table, Table, Table, or_
from app import mitre_data
from app import mitre_data
from app.detection_engine import run_detection
from app.extensions import db, login_manager
from app.models import alert, incident, log
from app.mitre_data import MITRE_TECHNIQUES


def create_app():

    app = Flask(__name__)

    # Configuration
    app.config["SECRET_KEY"] = "change-this-later"

    BASE_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )

    DATABASE_PATH = os.path.join(
        BASE_DIR,
        "instance",
        "socsentinel.db"
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + DATABASE_PATH
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "auth.login"

    # Import models
    from app.models.user import User
    from app.models.alert import Alert
    from app.models.incident import Incident
    from app.models.log import Log
    from app.models.detection_rule import DetectionRule
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register authentication routes
    from app.routes.auth import auth
    app.register_blueprint(auth)
    @app.route("/")
    def home():
        return redirect(url_for("auth.login"))
    # Dashboard
    @app.route("/dashboard")
    def dashboard():

        from app.models.alert import Alert

        total_events = Alert.query.count()

        critical_count = Alert.query.filter_by(
            severity="Critical"
        ).count()

        high_count = Alert.query.filter_by(
            severity="High"
        ).count()

        medium_count = Alert.query.filter_by(
            severity="Medium"
        ).count()

        low_count = Alert.query.filter_by(
            severity="Low"
        ).count()

        recent_alerts = Alert.query.order_by(
            Alert.timestamp.desc()
        ).limit(5).all()

        return render_template(
            "dashboard.html",
            total_events=total_events,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            recent_alerts=recent_alerts
        )
    # Alerts
    @app.route("/alerts")
    def alerts():

        from app.models.alert import Alert

        alerts = Alert.query.order_by(
            Alert.timestamp.desc()
        ).all()

        critical_count = Alert.query.filter_by(
            severity="Critical"
        ).count()

        high_count = Alert.query.filter_by(
            severity="High"
        ).count()

        medium_count = Alert.query.filter_by(
            severity="Medium"
        ).count()

        return render_template(
            "alerts.html",
            alerts=alerts,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count
        )
    @app.route("/alerts/<int:alert_id>")
    def alert_details(alert_id):

        from app.models.alert import Alert

        alert = Alert.query.get_or_404(alert_id)

        return render_template(
            "alert_details.html",
            alert=alert
        )
    @app.route("/alerts/<int:alert_id>/status", methods=["POST"])
    def update_alert_status(alert_id):

        from app.models.alert import Alert

        alert = Alert.query.get_or_404(alert_id)

        new_status = request.form.get("status")

        allowed_statuses = [
            "New",
            "Investigating",
            "Resolved"
        ]

        if new_status in allowed_statuses:

            alert.status = new_status

            db.session.commit()

        return redirect(
            url_for(
                "alert_details",
                alert_id=alert.id
            )
        )
    @app.route("/alerts/<int:alert_id>/create-incident", methods=["POST"])
    def create_incident(alert_id):

        from app.models.alert import Alert
        from app.models.incident import Incident

        alert = Alert.query.get_or_404(alert_id)

        # Check whether this alert already has an incident
        if alert.incident:
            return redirect(
                url_for(
                    "incident_details",
                    incident_id=alert.incident.id
                )
            )

        # Create the incident
        incident = Incident(
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            status="Open",
            alert_id=alert.id
        )

        db.session.add(incident)

        # The alert is now being investigated
        alert.status = "Investigating"

        db.session.commit()

        return redirect(
            url_for(
                "incident_details",
                 incident_id=incident.id
            )
        )
    # Incidents
    @app.route("/incidents")
    def incidents():

        from app.models.incident import Incident

        incidents = Incident.query.order_by(
            Incident.created_at.desc()
        ).all()

        return render_template(
            "incidents.html",
        incidents=incidents
        )
    @app.route("/incidents/<int:incident_id>")
    def incident_details(incident_id):

        from app.models.incident import Incident

        incident = Incident.query.get_or_404(
            incident_id
        )

        return render_template(
            "incident_details.html",
            incident=incident
        )
    @app.route("/incidents/<int:incident_id>/status",methods=["POST"])
    def update_incident_status(incident_id):

        from app.models.incident import Incident

        incident = Incident.query.get_or_404(
            incident_id
        )

        new_status = request.form.get("status")

        allowed_statuses = [
            "Open",
            "Investigating",
            "Resolved"
        ]

        if new_status in allowed_statuses:

            incident.status = new_status

            db.session.commit()

        return redirect(
            url_for(
                "incident_details",
                incident_id=incident.id
            )
        )

    # Log Explorer
    @app.route("/logs")
    def logs():

        from app.models.log import Log

        page = request.args.get(
            "page",
            1,
            type=int
        )

        search = request.args.get(
            "search",
            "",
            type=str
        ).strip()

        level = request.args.get(
            "level",
            "",
            type=str
           ).strip()

        source = request.args.get(
            "source",
            "",
            type=str
        ).strip()

        query = Log.query

        # Search
        if search:

            search_pattern = f"%{search}%"

            query = query.filter(
                or_(
                    Log.message.ilike(search_pattern),
                    Log.ip_address.ilike(search_pattern),
                    Log.username.ilike(search_pattern)
                    )
                )
        

        # Level filter
        if level:
            query = query.filter(
                Log.level == level
            )

        # Source filter
        if source:
            query = query.filter(
                Log.source == source
            )

        # Latest logs first
        query = query.order_by(
            Log.timestamp.desc()
        )

        logs_page = query.paginate(
            page=page,
            per_page=15,
            error_out=False
        )

        sources = [
            row[0]
            for row in db.session.query(
                Log.source
            ).distinct().order_by(
                Log.source
            ).all()
        ]

        return render_template(
            "logs.html",
            logs=logs_page.items,
            pagination=logs_page,
            search=search,
            level=level,
            source=source,
            sources=sources
        )
    @app.route("/logs/<int:log_id>")
    def log_details(log_id):

        from app.models.log import Log

        log = Log.query.get_or_404(log_id)

        return render_template(
            "log_details.html",
            log=log
        )
    
    # Detection Rules
    @app.route("/detection-rules")
    def detection_rules():

        from app.models.detection_rule import DetectionRule

        rules = DetectionRule.query.order_by(
            DetectionRule.id.asc()
        ).all()

        return render_template(
            "detection_rules.html",
            rules=rules
        )
    @app.route("/detection-rules/run", methods=["POST"])
    def run_detection_rules():

        from app.detection_engine import run_detection

        generated = run_detection()

        return redirect(
            url_for("detection_rules")
        )

    # MITRE ATT&CK
    @app.route("/mitre")
    def mitre():

        from app.models.alert import Alert
        from app.mitre_data import MITRE_TECHNIQUES

        techniques = []

        for technique_id, data in MITRE_TECHNIQUES.items():

            alert_count = Alert.query.filter_by(
                mitre_technique=technique_id
            ).count()

            techniques.append({
                "id": technique_id,
                "name": data["name"],
                "tactic": data["tactic"],
                "description": data["description"],
                "url": data["url"],
                "alert_count": alert_count
            })

        return render_template(
            "mitre.html",
            techniques=techniques
        )

    # Reports
    @app.route("/reports")
    def reports():

        from app.models.alert import Alert
        from app.models.incident import Incident
        from app.mitre_data import MITRE_TECHNIQUES

        total_alerts = Alert.query.count()

        critical_count = Alert.query.filter_by(
            severity="Critical"
        ).count()

        high_count = Alert.query.filter_by(
            severity="High"
        ).count()

        medium_count = Alert.query.filter_by(
            severity="Medium"
        ).count()

        low_count = Alert.query.filter_by(
            severity="Low"
        ).count()

        total_incidents = Incident.query.count()

        open_incidents = Incident.query.filter_by(
            status="Open"
        ).count()

        investigating_incidents = Incident.query.filter_by(
            status="Investigating"
        ).count()

        resolved_incidents = Incident.query.filter_by(
            status="Resolved"
        ).count()

        recent_alerts = Alert.query.order_by(
            Alert.timestamp.desc()
        ).limit(10).all()

        mitre_summary = []

        for technique_id, data in MITRE_TECHNIQUES.items():

            count = Alert.query.filter_by(
                mitre_technique=technique_id
            ).count()

            if count > 0:

                mitre_summary.append({
                    "id": technique_id,
                    "name": data["name"],
                    "tactic": data["tactic"],
                    "count": count
                })

        return render_template(
            "reports.html",
            total_alerts=total_alerts,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_incidents=total_incidents,
            open_incidents=open_incidents,
            investigating_incidents=investigating_incidents,
            resolved_incidents=resolved_incidents,
            recent_alerts=recent_alerts,
            mitre_summary=mitre_summary
        ) 
    @app.route("/reports/download")
    def download_report():

        from io import BytesIO

        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle
        )

        from app.models.alert import Alert
        from app.models.incident import Incident
        from app.mitre_data import MITRE_TECHNIQUES

        buffer = BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        story = []

        # Title

        story.append(
            Paragraph(
                "SOC Sentinel Security Report",
                styles["Title"]
            )
        )

        story.append(
            Spacer(1, 15)
        )

        story.append(
            Spacer(1, 15)
        )

        story.append(
                Paragraph(
                "Security Operations Center Report",
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 20)
        )


    # Alert statistics

        total_alerts = Alert.query.count()

        critical = Alert.query.filter_by(
            severity="Critical"
        ).count()

        high = Alert.query.filter_by(
            severity="High"
        ).count()

        medium = Alert.query.filter_by(
            severity="Medium"
        ).count()

        low = Alert.query.filter_by(
            severity="Low"
        ).count()


        story.append(
            Paragraph(
                "Alert Summary",
                styles["Heading2"]
            )
        )

        alert_data = [
            ["Metric", "Count"],
            ["Total Alerts", str(total_alerts)],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Medium", str(medium)],
            ["Low", str(low)]
        ]
    

        alert_table = Table(
            alert_data,
            colWidths=[250, 100]
        )

        alert_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ]
        )
    )

        story.append(alert_table)

        story.append(
            Spacer(1, 20)
        )


        # Incident summary

        total_incidents = Incident.query.count()

        open_count = Incident.query.filter_by(
            status="Open"
        ).count()

        investigating_count = Incident.query.filter_by(
            status="Investigating"
        ).count()

        resolved_count = Incident.query.filter_by(
            status="Resolved"
        ).count()


        story.append(
            Paragraph(
                "Incident Summary",
                styles["Heading2"]
            )
        )

        incident_data = [
            ["Metric", "Count"],
            ["Total Incidents", str(total_incidents)],
            ["Open", str(open_count)],
            ["Investigating", str(investigating_count)],
            ["Resolved", str(resolved_count)]
        ]

        incident_table = Table(
            incident_data,
            colWidths=[250, 100]
        )

        incident_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ]
        )
    )

        story.append(incident_table)

        story.append(
            Spacer(1, 20)
        )


        # MITRE summary

        story.append(
            Paragraph(
                "MITRE ATT&CK Summary",
                styles["Heading2"]
            )
        )

        mitre_data = [
            ["Technique", "Name", "Tactic", "Alerts"]
        ]

        for technique_id, data in MITRE_TECHNIQUES.items():
            count = Alert.query.filter_by(
                mitre_technique=technique_id
            ).count()

            if count > 0:
                mitre_data.append([
                    technique_id,
                    data["name"],
                    data["tactic"],
                    str(count)
                ])

        if len(mitre_data) == 1:
            mitre_data.append([
                "-",
                "No mapped techniques",
                "-",
                "0"
            ])

        mitre_table = Table(
            mitre_data,
            colWidths=[70, 160, 120, 50]
        )

        mitre_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ])
        )

        story.append(mitre_table)

        story.append(
            Spacer(1, 20)
        )

        # Recent alerts

        story.append(
            Paragraph(
                "Recent Security Alerts",
                styles["Heading2"]
            )
        )

        recent_alerts = Alert.query.order_by(
            Alert.timestamp.desc()
        ).limit(10).all()

        recent_data = [
            ["Alert", "Severity", "Status"]
        ]

        for alert in recent_alerts:
            recent_data.append([
                alert.title,
                alert.severity,
                alert.status
            ])

        if len(recent_data) == 1:
            recent_data.append([
                "No alerts",
                "-",
                "-"
            ])

        recent_table = Table(
            recent_data,
            colWidths=[260, 80, 80]
        )

        recent_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ])
        )

        story.append(recent_table)

        story.append(
            Spacer(1, 20)
        )

        story.append(
            Paragraph(
                "Generated by SOC Sentinel",
                styles["Normal"]
            )
        )

        document.build(story)

        buffer.seek(0)

        return (
            buffer.getvalue(),
            200,
            {
                "Content-Type": "application/pdf",
                "Content-Disposition":
                    "attachment; filename=soc_sentinel_report.pdf"
            }
        )


    # Create database tables
    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
