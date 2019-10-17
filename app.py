import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from fractions import Fraction

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies(default))
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)    # to store information specific to a user from one request to the next

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///farmNotes.db")

@app.route("/")
@login_required
def index():
    """Main """
    render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username to check
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # users reaching register via POST method
    if request.method == "POST":
        # Handling username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        username = request.form.get("username")
        if(not username):
            return apology("input is blank", 400)
        elif(len(rows) != 0):
            return apology("username already exists", 400)

        # Handling password
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if(not password):
            return apology("password is blank")
        elif(password != confirmation):
            return apology("passwords do not match")
        else:
            # When all are correct
            # INSERT the new user into users table
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password_hash)",
                       username=request.form.get("username"),
                       password_hash=generate_password_hash(password))

        # Remember user to automatically login once successfully registered
        just_registered = db.execute("SELECT * FROM users WHERE username = :username",
                                     username=request.form.get("username"))
        session["user_id"] = just_registered[0]["id"]
        session["user_username"] = just_registered[0]["username"]

        return redirect("/")

    # users reaching register via GET method
    else:
        return render_template("register.html")


# Personal touch: allow users to change their passwords
@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    """Change password."""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("changePassword.html")

     # User reached route via POST (as by submitting a form via POST)
    else:
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query all information about the user
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=session["user_username"])
        existingPassword = rows[0]["hash"]

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)  # if does not match, render an apology
        else:
            newPassword = request.form.get("newPassword")
            confPassword = request.form.get("confPassword")
            if(not newPassword):
                return apology("New password is blank")
            elif(newPassword != confPassword):
                return apology("New passwords do not match")
            else:
                # When all are correct
                db.execute("UPDATE users SET hash = :confPassword_hash WHERE username = :username", confPassword_hash=generate_password_hash(confPassword),
                           username=session["user_username"])

        # after altering, require user to login again
        return render_template("login.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
