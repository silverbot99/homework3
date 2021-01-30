from flask import Flask, render_template, flash, redirect, request, session, logging, url_for
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import *
from flask_otp import OTP

from random import *

app: Flask = Flask(__name__)
app.config['SECRET_KEY'] = '!9m@S-dThyIlW[pHQbN^'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost/mydatabase' #'mysql+pymysql://root:root@localhost/auth'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):

    __tablename__ = 'usertable'

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(50), unique=True)

    password = db.Column(db.String(256), unique=True)

@app.route('/')
def home():
    return render_template('index.html')


# User Registration Api End Point
@app.route('/register/', methods = ['GET', 'POST'])
def register():
    # Creating RegistrationForm class object
    form = RegisterForm(request.form)

    # Cheking that method is post and form is valid or not.
    if request.method == 'POST' and form.validate():

        # if all is fine, generate hashed password
        hashed_password = generate_password_hash(form.password.data, method='sha512')

        # create new user model object
        new_user = User(

            email = form.email.data,

            password = hashed_password )

        # saving user object into data base with hashed password
        db.session.add(new_user)

        db.session.commit()

        flash('You have successfully registered', 'success')

        # if registration successful, then redirecting to login Api
        return redirect(url_for('login'))

    else:

        # if method is Get, than render registration form
        return render_template('register.html', form = form)

# Login API endpoint implementation
@app.route('/login/', methods = ['GET', 'POST'])
def login():
    # Creating Login form object
    form = LoginForm(request.form)
    # verifying that method is post and form is valid
    if request.method == 'POST' and form.validate:
        # checking that user is exist or not by email
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None:
            # if user exist in database than we will compare our database hased password and password come from login form
            if check_password_hash(user.password, form.password.data):
                # if password is matched, allow user to access and save email and username inside the session
                flash('You have successfully logged in.', "success")
                session['logged_in'] = True
                session['email'] = user.email
                session['password'] = user.password
                # After successful login, redirecting to home page
                return redirect(url_for('home'))
            else:
                # if password is in correct , redirect to login page
                flash('Email or Password Incorrect', "error")
                return redirect(url_for('login'))
        else:
            app.logger.info('In Else')
            flash('Account not exist', "error")
    # rendering login page
    return render_template('login.html', form = form)


@app.route('/logout/')
def logout():
    # Removing data from session by setting logged_flag to False.
    session['logged_in'] = False
    # redirecting to home page
    return redirect(url_for('home'))

# One Time Login
mail = Mail(app)
app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'username@gmail.com'
app.config['MAIL_PASSWORD'] = '*************'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
otp = randint(000000,999999)
# otp = OTP()
# otp.init_app(app)

app.config["SECRET_KEY"] = "something"
app.config["DOMAIN"] = "www.XXX.com"

# @app.route('/qr')
# def qr():
#     """
#     Return a QR code for the secret key
#     The QR code is returned as file with MIME type image/png.
#     """
#     if session.get("OTPKEY", True):
#         # returns a 16 character base32 secret.
#         # Compatible with Google Authenticator
#         session["OTPKEY"] = otp.get_key()
#     img = otp.qr(session["OTPKEY"])
#     return send_file(img, mimetype="image/png")

@app.route('/verify/<string:password>')
def verify(password):
    """
    verify the One-Time Password
    """
    return str(otp.authenticate(session["OTPKEY"], password))

@app.route('/one_time_pass/')
def one_time_pass_direct():
    email = request.form["email"]
    msg = Message('OTP', sender='username@gmail.com', recipients=[email])
    msg.body = str(otp)
    mail.send(msg)
    return render_template('one_time_pass.html')

# @app.route('/verify/',methods=["POST"])
# def verify():
#     return render_template('verify.html')
#
@app.route('/one_time_pass/validate/', methods=["POST"])
def validate():
    user_otp = request.form['otp']
    if otp == int(user_otp):
        return "<h3> Email verfication is successfull</h3>"
    return "<h3> failture, OTP does not match</h3>"

if __name__ == '__main__':
    db.create_all()
    # running server
    app.run(debug=True)
