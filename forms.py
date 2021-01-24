from wtforms import Form, BooleanField, StringField, PasswordField, validators, TextAreaField, IntegerField
from wtforms.validators import DataRequired, ValidationError
import re

class LoginForm(Form):

    def check_validation(form, field):
        if len(field.data) < 8:
            raise ValidationError("Make sure your password is at lest 8 letters")
        elif re.search('[!@#$\-%^&*._]', field.data) is None:
            raise ValidationError("Make sure your password has a special character")
        elif re.search('[A-Z]', field.data) is None:
            raise ValidationError("Make sure your password has a capital letter in it")
        else:
            pass# raise ValidationError("Your password seems fine!")

    email = StringField("Email", validators=[validators.Length(min=7, max=50), validators.DataRequired(message="Please Fill This Field")])

    password = PasswordField("Password",validators=[check_validation,validators.DataRequired(message="Please Fill Password")])


# Creating Registration Form contains username, name, email, password and confirm password.

class RegisterForm(Form):
    def check_validation(form, field):
        if len(field.data) < 8:
            raise ValidationError("Make sure your password is at lest 8 letters")
        elif re.search('[!@#$\-%^&*._]', field.data) is None:
            raise ValidationError("Make sure your password has a special character")
        elif re.search('[A-Z]', field.data) is None:
            raise ValidationError("Make sure your password has a capital letter in it")
        else:
            pass# raise ValidationError("Your password seems fine!")

    email = StringField("Email", validators=[validators.Email(message="Please enter a valid email address")])

    password = PasswordField("Password", validators=[
        check_validation,

        validators.DataRequired(message="Please Fill This Field"),

        validators.EqualTo(fieldname="confirm", message="Your Passwords Do Not Match")
    ])

    confirm = PasswordField("Confirm Password", validators=[validators.DataRequired(message="Please Fill This Field")])
