# Copyright (c) * Raman
from itsdangerous import URLSafeTimedSerializer
from flask import Flask,request,jsonify,abort,make_response, redirect, url_for, render_template
from app import app,db
from passlib.hash import sha256_crypt
from response import Errors
from flask_mail import Mail, Message
from app.models import  Users
import threading



"""

This file contains routes for 
 - generate confirmation token for email                                    -   generate_confirmation_token()
 - confirming email token and returning true or false                       -   confirm_token()
 - send email for confirmation token                                        -   send_confirmation_email()
 - confirm token route for email                                            -   confirm()
 - forgot password route                                                    -   forgot()

"""



# This function helps in generating the encrypted string for the URL to be sent in the forgot password.
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer('g{|n9tX}!<8(#=@:KqrucE]wjnVy%1y@leFM^6U/vEHd;nYTJH1++oCa.RLc`/!') # Creates an object for TimedSerializer. 
    return serializer.dumps(email, salt='email_salt') # Returns encrypted string.


# This function helps in decrypting the serialized string created using the generate_confirmation_token() function got back from the email.
def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer('g{|n9tX}!<8(#=@:KqrucE]wjnVy%1y@leFM^6U/vEHd;nYTJH1++oCa.RLc`/!')
    try:
        email = serializer.loads(
            token,
            salt='email_salt',
            max_age=expiration
        )
    except:
        return False
    return email


# This is an with app context function to be run in the thread to send email in the background.
def send_mail_thread(msg):
    with app.app_context():
        mail.send(msg)
    return 'sent'


# This function will send the confirmation email.
def send_confirmation_email(email, user_name):
    mail = Mail()
    token = generate_confirmation_token(email) # Generating token to sent in the email
    msg = Message('Confirm Email',sender=('Sample', app.config['MAIL_DEFAULT_SENDER']),recipients=[email], reply_to = app.config['REPLY_TO'])
    link = app.config['API_HIT_URL'] + '/confirm_user/' + token # Creating the email URL
    msg.html = render_template('confirmationTemplate.html', confirm_url=format(link), user_name = user_name)
    threading.Thread(target = send_mail_thread, kwargs = {'msg': msg,}).start() # Calling email thread.
    return 'email sent'



# This function will send the forgot password email.
def forgot_password_mail(email, user_name):
    mail = Mail()
    token = generate_confirmation_token(email) # Generating token to sent in the email.
    msg = Message('Forgot Password',sender=('Sample', app.config['MAIL_DEFAULT_SENDER']),recipients=[email], reply_to = app.config['REPLY_TO'])
    link = app.config['API_HIT_URL'] + '/newPassword/' + token # Creating the email URL.
    msg.html = render_template('forgotPasswordTemplate.html', confirm_url=format(link), user_name = user_name)
    threading.Thread(target = send_mail_thread, kwargs = {'msg': msg,}).start() # Calling email thread.
    return 'email sent'



# This route is the URL sent in the email and will open a template for the confirmation message.
@app.route('/confirm_user/<token>')
def confirm(token):
    email= confirm_token(token)
    confirm = Users.query.filter_by(email=email).first()
    if confirm.status is False:
        confirm.status = True
        db.session.commit()
        return render_template('confirmed.html', message='Email has been confirmed successfully!', user_name=confirm.name)

    else:
        return render_template('confirmed.html', message='Your email is already confirmed!', user_name=confirm.name)
    

# This route is for the forgot password API hit to change the password for a user.
@app.route('/forgot/<token>', methods = ['POST'])
def forgot(token):
    email= confirm_token(token)
    user = Users.query.filter_by(email=email).first()
    if not user:
        return make_response(jsonify({'message':Errors.UNKNOWN_USER,'status' : 401}))
    user.password = sha256_crypt.encrypt(request.json.get('password'))
    db.session.commit()
    return make_response(jsonify({'message':Errors.CHANGE_PASSWORD_SUCCESS,'status' : 201}))
    



mail = Mail(app)
