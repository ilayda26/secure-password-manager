from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect
import os
import random
import string

app = Flask(__name__)

app.config["SECRET_KEY"] = "temporary-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///password_manager.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

KEY_FILE = "secret.key"

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
else:
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()

cipher = Fernet(key)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    website = db.Column(
        db.String(100),
        nullable=False
    )

    account_username = db.Column(
        db.String(100),
        nullable=False
    )

    encrypted_password = db.Column(
        db.Text,
        nullable=False
    )


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash("Username or email already exists!", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration completed successfully!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password!", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=session["username"])


@app.route("/add-password", methods=["GET", "POST"])
def add_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        website = request.form["website"]
        account_username = request.form["account_username"]
        password = request.form["password"]

        encrypted_password = cipher.encrypt(password.encode()).decode()

        new_password = PasswordEntry(
            user_id=session["user_id"],
            website=website,
            account_username=account_username,
            encrypted_password=encrypted_password
        )

        db.session.add(new_password)
        db.session.commit()

        flash("Password saved successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_password.html")


@app.route("/view-passwords")
def view_passwords():
    if "user_id" not in session:
        return redirect(url_for("login"))

    passwords = PasswordEntry.query.filter_by(user_id=session["user_id"]).all()

    for password in passwords:
        password.decrypted_password = cipher.decrypt(
            password.encrypted_password.encode()
        ).decode()

    return render_template("view_passwords.html", passwords=passwords)


@app.route("/delete-password/<int:password_id>")
def delete_password(password_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    password = PasswordEntry.query.filter_by(
        id=password_id,
        user_id=session["user_id"]
    ).first()

    if password:
        db.session.delete(password)
        db.session.commit()
        flash("Password deleted successfully!", "success")

    return redirect(url_for("view_passwords"))


@app.route("/generate-password", methods=["GET", "POST"])
def generate_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    generated_password = ""

    if request.method == "POST":
        length = int(request.form["length"])

        characters = (
            string.ascii_letters
            + string.digits
            + string.punctuation
        )

        generated_password = "".join(
            random.choice(characters)
            for _ in range(length)
        )

    return render_template(
        "generate_password.html",
        generated_password=generated_password
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)