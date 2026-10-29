import os
from dotenv import load_dotenv

from flask import (
    Flask, render_template, request, url_for,
    redirect, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from sqlalchemy import inspect, text
from mangum import Mangum

# Load environment variables from .env
load_dotenv()

# Initialize Flask
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# Session cookie settings
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "false").lower() == "true"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Brevo SMTP settings
app.config["MAIL_SERVER"] = "smtp-relay.brevo.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ["MAIL_USERNAME"]
app.config["MAIL_PASSWORD"] = os.environ["MAIL_PASSWORD"]

# Use a sender address verified in your Brevo account
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get(
    "MAIL_DEFAULT_SENDER",
    os.environ["MAIL_USERNAME"]
)

# Initialize database, email, and login manager
db = SQLAlchemy(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# User model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(250), nullable=False)
    is_verified = db.Column(
        db.Boolean, default=False, nullable=False
    )


# Create the table and migrate the missing verification column
with app.app_context():
    db.create_all()

    inspector = inspect(db.engine)
    columns = {
        column["name"]
        for column in inspector.get_columns("users")
    }

    if "is_verified" not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE users "
                    "ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT 0"
                )
            )
        print("Migration complete: is_verified column added.")
    else:
        print("Database already contains is_verified.")

    print("Application folder:", app.root_path)
    print("Instance folder:", app.instance_path)
    print("Database URL:", db.engine.url)
    print("Users columns:", inspect(db.engine).get_columns("users"))


# Load a user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))


# Home route
@app.route("/")
def home():
    return redirect(url_for("login"))


# Generate a signed verification token
def generate_verification_token(email):
    return serializer.dumps(email, salt="email-verification")


# Send verification email through Brevo
def send_verification_email(user_email):
    token = generate_verification_token(user_email)

    verification_url = url_for(
        "verify_email",
        token=token,
        _external=True
    )

    message = Message(
        subject="Verify Your Email Address",
        recipients=[user_email],
        body=(
            "Thank you for registering!\n\n"
            "Click this link to verify your email address:\n\n"
            f"{verification_url}\n\n"
            "This link expires in 30 minutes.\n"
            "If you did not register, ignore this email."
        )
    )

    mail.send(message)


# Registration route
@app.route("/registration", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            return render_template(
                "registration.html",
                error="Please fill in all required fields."
            )

        if len(password) < 8 or len(password) > 12:
            return render_template(
                "registration.html",
                error="Password must be 8 to 12 characters long."
            )

        if Users.query.filter_by(username=username).first():
            return render_template(
                "registration.html",
                error="Username already taken!"
            )

        if Users.query.filter_by(email=email).first():
            return render_template(
                "registration.html",
                error="Email already registered."
            )

        hashed_password = generate_password_hash(password)

        new_user = Users(
            username=username,
            email=email,
            phone=phone,
            password=hashed_password,
            is_verified=False
        )

        db.session.add(new_user)
        db.session.commit()

        try:
            send_verification_email(new_user.email)
        except Exception:
            app.logger.exception("Verification email sending failed")
            flash(
                "Your account was saved, but the verification email "
                "could not be sent. Check the email settings or contact "
                "the administrator.",
                "error"
            )
            return redirect(url_for("login"))

        flash(
            "Registration successful! Check your email and click "
            "the verification link before logging in.",
            "success"
        )
        return redirect(url_for("login"))

    return render_template("registration.html")


# Verify email ownership
@app.route("/verify-email/<token>")
def verify_email(token):
    try:
        email = serializer.loads(
            token,
            salt="email-verification",
            max_age=1800
        )
    except SignatureExpired:
        return render_template(
            "verify_email.html",
            message="Verification link expired.",
            details="Please request a new verification link."
        )
    except BadSignature:
        return render_template(
            "verify_email.html",
            message="Invalid verification link.",
            details="Please use the link from your verification email."
        )

    user = Users.query.filter_by(email=email).first()

    if user is None:
        return render_template(
            "verify_email.html",
            message="Account not found.",
            details="Please register before verifying your email."
        )

    if user.is_verified:
        return render_template(
            "verify_email.html",
            message="Email already verified.",
            details="You can log in to your account."
        )

    user.is_verified = True
    db.session.commit()

    return render_template(
        "verify_email.html",
        message="Email verified successfully!",
        details="Your account is verified. You can now log in."
    )


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = Users.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                return render_template(
                    "login.html",
                    error="Please verify your email before logging in."
                )

            login_user(user)
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email or password."
        )

    return render_template("login.html")


# Dashboard route
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=current_user.username
    )


# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("login"))


# AWS Lambda handler
handler = Mangum(app)


if __name__ == "__main__":
    app.run(debug=True)

