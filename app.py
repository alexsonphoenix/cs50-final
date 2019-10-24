import os
import datetime

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from fractions import Fraction
from flask_wtf import RecaptchaField, FlaskForm
from wtforms import StringField, DateTimeField, PasswordField, IntegerField
from wtforms.validators import InputRequired, Length, NumberRange
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect

from helpers import apology, login_required


# To enable CSRF protection globally for a Flask app, register the CSRFProtect extension.
csrf = CSRFProtect()

# Configure application
app = Flask(__name__)
Bootstrap(app)
csrf.init_app(app)  # apply it lazily

# CSRF uses this key to prevent forms being submitted by people not on the route
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or \
    'abc123ced456'

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Recaptcha by Google to ensure robots don't mess with the database
app.config["RECAPTCHA_PUBLIC_KEY"] = '6LfJAL8UAAAAAH8h3LZbmm7F7w5Mi-VkhKZPc328'
app.config["RECAPTCHA_PRIVATE_KEY"] = '6LfJAL8UAAAAAN7_Kwsc0uRGm0GrI9HOso2Ud-Ef'
app.config["TESTING"] = True

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
    # Page Title
    username = session["user_username"]

    return render_template("index.html")


# Form for login
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    form = LoginForm()

    # User reached route via POST (as by submitting a form via POST)
    if form.validate_on_submit():
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
    return render_template("login.html", form = form)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    # get user's input from HTTP parameter passing from AJAX $.get
    username_input = request.args.get("username")
    print(username_input)
    # Query database for existing usernames
    username_database = db.execute("SELECT username FROM users")
    username_database_list = [username_database[i]["username"] for i in range(len(username_database))]

    # length at least 1 and does not already belong to a user in the database
    if(len(username_input) > 1 and (username_input not in username_database_list)):
        return jsonify(True)
    else:
        return jsonify(False)


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


# Form for setting route
class settingForm(FlaskForm):
    trackingYears = IntegerField('Tracking Years')

    crop = StringField('Crop')
    cropUnit = StringField('Crop Unit')
    livestock = StringField('LiveStock')
    livestockUnit = StringField('LiveStock Unit')
    cropEx = StringField('Crop Expense')
    cropExUnit = StringField('Crop Expense Unit')
    livestockEx = StringField('LiveStock Expense')
    livestockExUnit = StringField('LiveStock Expense Unit')


@app.route("/setting", methods=["GET", "POST"])
@login_required
def setting():
    """Setting Page."""
    form = settingForm()

    # User reached route via POST (as by clicking a link or via redirect)
    if form.validate_on_submit():
        # Add data into the database

        # Query user in [users] table
        user_query = db.execute("SELECT * FROM users WHERE id = :user_id",user_id = session["user_id"])

        # update trackingYears: (Originally: NULL)
        db.execute("UPDATE users SET trackingYears = :trackingYears WHERE id = :user_id", trackingYears=int(request.form.get("trackingYears")),
                   user_id = session["user_id"])


        return render_template("yourFarm.html")


    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("setting.html", form=form)




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


@app.route("/yourFarm")
@login_required
def yourFarm():
    trackingYears = db.execute("SELECT trackingYears FROM users WHERE id =:user_id", user_id=session["user_id"])

    return render_template("yourFarm.html", trackingYears=int(trackingYears))


@app.route("/calculators")
@login_required
def calculators():
    return render_template("calculators.html")


@app.route("/dailyNotes")
@login_required
def dailyNotes():
    return render_template("dailyNotes.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
