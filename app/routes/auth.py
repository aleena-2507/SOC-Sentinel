from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_login import login_user, logout_user

from app.models import user
from app.models.user import User


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        print("LOGIN ATTEMPT")
        print("Username entered:", repr(username))
        print("User found:", user is not None)

        if user:
            print("Password valid:", user.check_password(password))

        if user and user.check_password(password):
            login_user(user)

            print("LOGIN SUCCESS")

            return redirect(url_for("dashboard"))

        print("LOGIN FAILED")

        flash("Invalid username or password.", "error")    

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template("login.html")


@auth.route("/logout")
def logout():

    logout_user()

    return redirect(
        url_for("auth.login")
    )