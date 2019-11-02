import os
import datetime

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from fractions import Fraction
from flask_wtf import RecaptchaField, FlaskForm
from wtforms import StringField, DateField, PasswordField, IntegerField, SubmitField, SelectField, FloatField, TextAreaField
from wtforms.validators import InputRequired, Length, NumberRange, DataRequired, Optional
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect
from wtforms.fields.html5 import DateField
from wtforms.widgets import html5
from wtforms.ext.sqlalchemy.fields import QuerySelectField

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


# QUERY to display
# Query users
def qry_user():
    return db.execute("SELECT * FROM users WHERE id = :user_id",user_id = session["user_id"])
# Query Crops
def qry_crops():
    return db.execute("SELECT * FROM crops WHERE user_id = :user_id", user_id=session["user_id"])
# Query Crop Expenses
def qry_cropEx():
    return db.execute("SELECT * FROM cropExpenses WHERE user_id = :user_id", user_id=session["user_id"])
# Query livestocks
def qry_livestocks():
    return db.execute("SELECT * FROM livestocks WHERE user_id = :user_id", user_id=session["user_id"])
# Query livestock expenses
def qry_livestockEx():
    return db.execute("SELECT * FROM livestockExpenses WHERE user_id = :user_id", user_id=session["user_id"])


# SETTING PAGE:
# Forms for setting route
class trackingYearsForm(FlaskForm):
    trackingYears = IntegerField('Tracking Years', validators=[NumberRange(min=1, max=10, message="between 1 and 10 years"), InputRequired()])
    submit1 = SubmitField('Save')

class cropForm(FlaskForm):
    crop_name = StringField('Crop Name', validators=[InputRequired()])
    cropUnit = StringField('Crop Measurement', validators=[InputRequired()])
    submit2 = SubmitField('Add')

class cropExForm(FlaskForm):
    cropEx = StringField('Crop Expense', validators=[InputRequired()])
    cropExUnit = StringField('Crop Expense measurement', validators=[InputRequired()])
    submit3 = SubmitField('Add')

class livestockForm(FlaskForm):
    livestock = StringField('LiveStock', validators=[InputRequired()])
    livestockUnit = StringField('LiveStock measurement', validators=[InputRequired()])
    submit4 = SubmitField('Add')

class livestockExForm(FlaskForm):
    livestockEx = StringField('LiveStock Expense', validators=[InputRequired()])
    livestockExUnit = StringField('LiveStock Expense measurement', validators=[InputRequired()])
    submit5 = SubmitField('Add')

@app.route("/setting", methods=["GET", "POST"])
@login_required
def setting():
    """Setting Page."""
    form1 = trackingYearsForm(prefix="form1")
    form2 = cropForm(prefix="form2")
    form3 = cropExForm(prefix="form3")
    form4 = livestockForm(prefix="form4")
    form5 = livestockExForm(prefix="form5")

    # User reached route via POST : HANDLING TRACKING YEARS SETTING
    if form1.submit1.data and form1.validate():
        # update trackingYears: (Originally: NULL)
        db.execute("UPDATE users SET trackingYears = :trackingYears WHERE id = :user_id",    trackingYears=int(request.form.get("form1-trackingYears")),
               user_id = session["user_id"])

        return redirect("/setting")

    # User reached route via POST : HANDLING CROPS SETTING
    if form2.submit2.data and form2.validate():
        # insert CROP data into the database
        db.execute("INSERT INTO crops (user_id, cropName, unitName) VALUES (:user_id, :crop_name, :unit_name)", user_id=session["user_id"],
                        crop_name=request.form.get("form2-crop_name"),
                        unit_name=request.form.get("form2-cropUnit"))

        return redirect("/setting")

    # User reached route via POST : HANDLING CROP EXPENSES SETTING
    if form3.submit3.data and form3.validate():
        # insert CROP EXPENSE data into the database
        db.execute("INSERT INTO cropExpenses (user_id, cropExName, cropExUnit) VALUES (:user_id, :cropEx, :cropExUnit)", user_id=session["user_id"],
                        cropEx=request.form.get("form3-cropEx"),
                        cropExUnit=request.form.get("form3-cropExUnit"))

        return redirect("/setting")

    # User reached route via POST : HANDLING LIVESTOCK SETTING
    if form4.submit4.data and form4.validate():
        # insert LIVESTOCK data into the database
        db.execute("INSERT INTO livestocks (user_id, livestockName, livestockUnit) VALUES (:user_id, :livestock, :livestockUnit)", user_id=session["user_id"],
                        livestock=request.form.get("form4-livestock"),
                        livestockUnit=request.form.get("form4-livestockUnit"))

        return redirect("/setting")

    # User reached route via POST : HANDLING LIVESTOCK EXPENSES SETTING
    if form5.submit5.data and form5.validate():
        # insert LIVESTOCK EXPENSE data into the database
        db.execute("INSERT INTO livestockExpenses (user_id, livestockExName, livestockExUnit) VALUES (:user_id, :livestockEx, :livestockExUnit)", user_id=session["user_id"],
                        livestockEx=request.form.get("form5-livestockEx"),
                        livestockExUnit=request.form.get("form5-livestockExUnit"))

        return redirect("/setting")



    # Query to display current inventories
    qry_crops = db.execute("SELECT * FROM crops WHERE user_id = :user_id", user_id=session["user_id"])
    qry_cropEx = db.execute("SELECT * FROM cropExpenses WHERE user_id = :user_id", user_id=session["user_id"])
    qry_livestocks = db.execute("SELECT * FROM livestocks WHERE user_id = :user_id", user_id=session["user_id"])
    qry_livestockEx = db.execute("SELECT * FROM livestockExpenses WHERE user_id = :user_id", user_id=session["user_id"])

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("setting.html", form1=form1,
                                            form2=form2,
                                            form3=form3,
                                            form4=form4,
                                            form5=form5,
                                            qry_crops=qry_crops,
                                            qry_cropEx=qry_cropEx,
                                            qry_livestocks=qry_livestocks,
                                            qry_livestockEx=qry_livestockEx)


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


@app.route("/yourFarm") # Only displaying
@login_required
def yourFarm():
    # Query user in [users] table
    user_query = qry_user()

    #Query crops,livestocks,cropExpenses, livestockExpenses
    crops=qry_crops()
    livestocks=qry_livestocks()
    cropExs=qry_cropEx()
    livestockExs=qry_livestockEx()

    def amountCrop(crop_id, year):
        return db.execute("SELECT SUM(crop_amount) as Crop_Amount_Sum FROM dailyHarvestCrop WHERE user_id = :user_id AND crop_id=:crop_id AND dates BETWEEN :startDate AND :endDate", user_id=session["user_id"],
                                                crop_id=crop_id,
                                                startDate=datetime.strptime(str(year)+'/1/1', '%Y/%m/%d'),
                                                endDate=datetime.strptime(str(year)+'/12/31', '%Y/%m/%d'))

    def amountLivestock(livestock_id, year):
        return db.execute("SELECT SUM(livestock_amount) as Livestock_Amount_Sum FROM dailyHarvestLivestock WHERE user_id = :user_id AND livestock_id=:livestock_id AND dates BETWEEN :startDate AND :endDate", user_id=session["user_id"],
                                                livestock_id=livestock_id,
                                                startDate=datetime.strptime(str(year)+'/1/1', '%Y/%m/%d'),
                                                endDate=datetime.strptime(str(year)+'/12/31', '%Y/%m/%d'))

    def amountCropEx(cropEx_id, year):
        return db.execute("SELECT SUM(cropEx_amount) as CropEx_Amount_Sum FROM dailySpendCrop WHERE user_id = :user_id AND cropEx_id=:cropEx_id AND dates BETWEEN :startDate AND :endDate", user_id=session["user_id"],
                                                cropEx_id=cropEx_id,
                                                startDate=datetime.strptime(str(year)+'/1/1', '%Y/%m/%d'),
                                                endDate=datetime.strptime(str(year)+'/12/31', '%Y/%m/%d'))

    def amountLivestockEx(livestockEx_id, year):
        return db.execute("SELECT SUM(LivestockEx_amount) as LivestockEx_Amount_Sum FROM dailySpendLivestock WHERE user_id = :user_id AND livestockEx_id=:livestockEx_id AND dates BETWEEN :startDate AND :endDate", user_id=session["user_id"],
                                                livestockEx_id=livestockEx_id,
                                                startDate=datetime.strptime(str(year)+'/1/1', '%Y/%m/%d'),
                                                endDate=datetime.strptime(str(year)+'/12/31', '%Y/%m/%d'))

    # Get the current year
    currentYear = datetime.now().year
    # Display Years:
    displayYears = [currentYear-year for year in range(user_query[0]["trackingYears"])]
    print('display years are: ', displayYears)

    return render_template("yourFarm.html", user_query=user_query,
                                            displayYears=displayYears,
                                            crops=crops,
                                            livestocks=livestocks,
                                            cropExs=cropExs,
                                            livestockExs=livestockExs,
                                            amountCrop=amountCrop,
                                            amountLivestock=amountLivestock,
                                            amountCropEx=amountCropEx,
                                            amountLivestockEx=amountLivestockEx)


@app.route("/calculators")
@login_required
def calculators():
    return render_template("calculators.html")



# Forms for dailyNotes
class harvestCrop(FlaskForm):
    dateNote1 = DateField('Choose Harvesting Date', format='%Y-%m-%d', validators=[InputRequired()])
    crop_name = SelectField(u'Choose Crop', coerce=int, validators=[InputRequired()])
    crop_amount = FloatField('Harvesting Amount',widget=html5.NumberInput(), validators=[InputRequired()])
    crop_money = FloatField('Monetary equivalent',widget=html5.NumberInput(), validators=[InputRequired()])
    note = TextAreaField(u'Note', validators =[Optional(), Length(max=200)])
    submit1 = SubmitField('Harvested')

class harvestLivestock(FlaskForm):
    dateNote2 = DateField('Choose Harvesting Date', format='%Y-%m-%d', validators=[InputRequired()])
    livestock_name = SelectField(u'Choose Livestock', coerce=int, validators=[InputRequired()])
    livestock_amount = IntegerField('Harvesting Amount',widget=html5.NumberInput(), validators=[InputRequired()])
    livestock_money = IntegerField('Monetary equivalent',widget=html5.NumberInput(), validators=[InputRequired()])
    note = TextAreaField(u'Note', validators =[Optional(), Length(max=200)])
    submit2 = SubmitField('Harvested')

class spendCrop(FlaskForm):
    dateNote3 = DateField('Choose Spending Date', format='%Y-%m-%d',validators= [InputRequired()])
    cropEx_name = SelectField(u'Choose Crop Expense', coerce=int, validators=[InputRequired()])
    cropEx_amount = IntegerField('Spending Amount',widget=html5.NumberInput(), validators=[InputRequired()])
    cropEx_money = IntegerField('Monetary equivalent',widget=html5.NumberInput(), validators=[InputRequired()])
    note = TextAreaField(u'Note', validators =[Optional(), Length(max=200)])
    submit3 = SubmitField('Spent')

class spendLivestock(FlaskForm):
    dateNote4 = DateField('Choose Spending Date', format='%Y-%m-%d', validators=[InputRequired()])
    livestockEx_name = SelectField(u'Choose Livestock Expense', coerce=int, validators=[InputRequired()])
    livestockEx_amount = IntegerField('Spending Amount',widget=html5.NumberInput(), validators=[InputRequired()])
    livestockEx_money = IntegerField('Monetary equivalent',widget=html5.NumberInput(), validators=[InputRequired()])
    note = TextAreaField(u'Note', validators =[Optional(), Length(max=200)])
    submit4 = SubmitField('Spent')

@app.route("/dailyNotes", methods=["GET", "POST"])
@login_required
def dailyNotes():
    """dailyNotes Page."""
    form1 = harvestCrop(prefix="form1")
    form2 = harvestLivestock(prefix="form2")
    form3 = spendCrop(prefix="form3")
    form4 = spendLivestock(prefix="form4")

    # Fill in choices for Harvest CROP form
    crops = [(crop["id"],crop["cropName"]+ ' - ' +crop["unitName"]) for crop in qry_crops()]
    form1.crop_name.choices = crops

    # Fill in choices for Harvest LIVESTOCK form
    livestocks = [(livestock["id"],livestock["livestockName"]+ ' - ' +livestock["livestockUnit"]) for livestock in qry_livestocks()]
    form2.livestock_name.choices = livestocks

    # Fill in choices for Spending CROP EXPENSES form
    cropExs = [(cropEx["id"],cropEx["cropExName"]+ ' - ' +cropEx["cropExUnit"]) for cropEx in qry_cropEx()]
    form3.cropEx_name.choices = cropExs

    # Fill in choices for Spending LIVESTOCK EXPENSESform
    livestockExs = [(livestockEx["id"],livestockEx["livestockExName"]+ ' - ' +livestockEx["livestockExUnit"]) for livestockEx in qry_livestockEx()]
    form4.livestockEx_name.choices = livestockExs


    # User reached route via GET : SHOWING INPUT FORM
    if request.method == 'GET':
        print("Serving GET requessttt NOWWWWWW")
        return render_template("dailyNotes.html", form1=form1,
                                                    form2=form2,
                                                    form3=form3,
                                                    form4=form4)


    # User reached route via POST : HANDLING TRACKING YEARS
    else:
        if form1.submit1.data and form1.validate():
            # INSERT New Harvest CROP into dailyHarvestCrop table:
            db.execute("INSERT INTO dailyHarvestCrop (user_id, dates, crop_id, crop_amount, crop_money, note) VALUES (:user_id, :dates, :crop_id, :crop_amount, :crop_money, :note)", user_id=session["user_id"],
                                                dates=request.form.get("form1-dateNote1"),
                                                crop_id=int(request.form.get("form1-crop_name")),
                                                crop_amount=float(request.form.get("form1-crop_amount")),
                                                crop_money=float(request.form.get("form1-crop_money")),
                                                note=request.form.get("form1-note"))

            return redirect("/dailyNotes")

        if form2.submit2.data and form2.validate():
            # INSERT New Harvest LIVESTOCK into dailyHarvestLivestock table:
            db.execute("INSERT INTO dailyHarvestLivestock (user_id, dates, livestock_id, livestock_amount, livestock_money, note) VALUES (:user_id, :dates, :livestock_id, :livestock_amount, :livestock_money, :note)",
                    user_id=session["user_id"],
                    dates=request.form.get("form2-dateNote2"),
                    livestock_id=int(request.form.get("form2-livestock_name")),
                    livestock_amount=float(request.form.get("form2-livestock_amount")),
                    livestock_money=float(request.form.get("form2-livestock_amount")),
                    note=request.form.get("form2-note"))
            return redirect("/dailyNotes")

        if form3.submit3.data and form3.validate():
            # INSERT New Expenditure Crop into dailySpendCrop table:
            db.execute("INSERT INTO dailySpendCrop (user_id, dates, cropEx_id, cropEx_amount, cropEx_money, note) VALUES (:user_id, :dates, :cropEx_id, :cropEx_amount, :cropEx_money, :note)",
                    user_id=session["user_id"],
                    dates=request.form.get("form3-dateNote3"),
                    cropEx_id=int(request.form.get("form3-cropEx_name")),
                    cropEx_amount=float(request.form.get("form3-cropEx_amount")),
                    cropEx_money=float(request.form.get("form3-cropEx_money")),
                    note=request.form.get("form3-note"))
            return redirect("/dailyNotes")

        if form4.submit4.data and form4.validate():
            # INSERT new LIVESTOCK EXPENSES into dailySpendCrop table:
            db.execute("INSERT INTO dailySpendLivestock (user_id, dates, livestockEx_id, livestockEx_amount, livestockEx_money, note) VALUES (:user_id, :dates, :livestockEx_id, :livestockEx_amount, :livestockEx_money, :note)",
                    user_id=session["user_id"],
                    dates=request.form.get("form4-dateNote4"),
                    livestockEx_id=int(request.form.get("form4-livestockEx_name")),
                    livestockEx_amount=float(request.form.get("form4-livestockEx_amount")),
                    livestockEx_money=float(request.form.get("form4-livestockEx_money")),
                    note=request.form.get("form4-note"))
            return redirect("/dailyNotes")




def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
