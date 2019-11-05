# Copyright (c) * Raman
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length

# Form class for the forgot password form.
class ForgotForm(FlaskForm):
    # Defining fields for the forgot password form with their properties.
    Password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    ConfirmPassword = PasswordField('Confirm Password', validators=[DataRequired()], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Change Password')

