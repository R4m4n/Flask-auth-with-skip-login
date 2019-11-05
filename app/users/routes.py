# Copyright (c) * Raman
from app import app,db
from flask import Flask,request,jsonify,abort,make_response, redirect, url_for, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt_identity, verify_jwt_in_request
from app.models import  Users, Devices, Review
from app.emails import generate_confirmation_token, confirm_token, send_confirmation_email, forgot_password_mail
from flask_mail import Mail, Message
from response import Errors
from flasgger import swag_from, Swagger
from sqlalchemy.exc import SQLAlchemyError, DBAPIError, IntegrityError
from app.users.forms import ForgotForm
import json, os, uuid, re, datetime, calendar, yaml, requests



"""

This file contains routes for 
 - register user                                    -   addUser()
 - perform login action                             -   login()
 - forgotPassword API                               -   forgotPassword()
 - skip login                                       -   skipLogin()

"""

jwt = JWTManager(app)


# this function checks weather the file uploaded has the proper extension that are defined in the config file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



@app.route('/')
def empty():
    return 'Dev Server.'

# This route is used to register the users along with their user_type and phone number and password
# Tmail is registered by the user for reveving the mails
# A mail is sent in case of the user which also has to be verified by the link in it.
@app.route('/users',methods=['POST'])
def addUser():
    try:
        if len(request.form.get('password')) < 6: # Check if the password is greter than 6.
            return make_response(jsonify({'message':Errors.PASSWORD_VALIDATION,'status' : 401})), 400
        elif re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.form.get('email')) is None: # Check if the given string is an email
            return make_response(jsonify({'message':Errors.EMAIL_VALIDATION,'status' : 401})), 400
        elif len(request.form.get('name')) > 50: # Check if the name is not greater than 50 characters.
            return make_response(jsonify({'message':Errors.NAME_LENGTH_VALIDATION,'status' : 401})), 400

        data = {}
        dataList = []
        usersjson = {}
        # Get all the values from the requested form-data.
        name = request.form.get('name')
        email = request.form.get('email')  
        gender = request.form.get('gender')  
        password = sha256_crypt.encrypt(request.form.get('password')) # Encrypt the password to sha256 hash.
        device_token = request.form.get('device_token') 
        device_type = request.form.get('device_type') 
        # Creating a 'Users' object.
        user= Users(
            name = name,
            email = email, 
            password = password, 
            gender =gender,
            status = False
        )
        
        
        db.session.add(user) # Add Users object to the db session.
        db.session.commit() # Commit db session.
        # Now store the device token in the Devices table by creating the 'Devices' object.
        devices = Devices(
            device_token = device_token,
            device_type = device_type,
            user_id = user.id
        ) 
        db.session.add(devices)
        db.session.commit()
        send_confirmation_email(email, user_name = name) # Sending a confirmation email to the user registered.
        finalData = {'message':Errors.REGISTERATION_SECCESS,'status' : 201}
        usersjson = json.dumps(finalData, indent=4, sort_keys=True) # Creating a final user response.
        return make_response(usersjson)
    except (SQLAlchemyError, DBAPIError,IntegrityError) as e:
        print (e.orig.args)
        db.session.rollback() # If an exception occurs then a db session rollback is called.
        try:
            # Check if the error gives duplicate entry by checking the code to 1062. If the user already exists and the status is true then an error with appropriate message is thrown else if user's status is False then the entries are renewed and a confirmation email is sent
            if e.orig.args[0] == 1062:
                user = Users.query.filter_by(email = email).first()
                # Check if the status is false in the users object so that the user can be registered again.
                if not (user.status): 
                    for incoming in request.form:
                        # Updating already registered data to the new incoming values.
                        if 'password' == incoming:
                            setattr(user, 'password', sha256_crypt.encrypt(request.form.get('password')))
                        else:  
                            setattr(user, incoming, request.form.get(incoming)) # setattr() function to add the values to db session
                  
                    setattr(user, 'updated_at', datetime.datetime.utcnow())
                    db.session.commit()
                    device_token = request.form.get('device_token') 
                    device_type = request.form.get('device_type') 
                    # Deleting device token from the devices table if there already exists for the same user.
                    if Devices.query.filter_by(device_token = device_token).first():
                        Devices.query.filter_by(device_token = device_token).delete()
                        db.session.commit()
                    # Registering device token again for the user.
                    devices = Devices(
                        device_token = device_token,
                        device_type = device_type,
                        user_id = user.id
                    )
                    db.session.add(devices)
                    db.session.commit()
                    send_confirmation_email(user.email, user_name = user.name) # Send confirmation email.
                    finalData = {'message':Errors.REGISTERATION_SECCESS,'status' : 201}
                    usersjson = json.dumps(finalData, indent=4, sort_keys=True)
                    return make_response(usersjson)
                else:
                    return make_response(jsonify({'message':Errors.EMAIL_ALREADY_REGISTERED,'status' : 401})), 400
            else: 
                # Error if the error was not related to duplicate entry and the false status
                    return make_response(jsonify({'message':Errors.UNKNOWN_ERROR,'status' : 401})), 400
        except Exception as e:
            if e.orig.args[0] == 1062:
                if 'email' in e.orig.args[1]:
                    # If email keyword is in the error thrown by the mysql, then the message is sent in the response
                    return make_response(jsonify({'message':Errors.EMAIL_ALREADY_REGISTERED,'status' : 401})), 400
            else:
                make_response(jsonify({'message' : str(e), 'status' : 401})), 400




# This route is used to perform the login action and access_token is returned in response
# created using the JWT and the user object is used to create the JWT 
# Email and password are used to login 
@app.route('/login',methods = ['POST'])
def login():
    if re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.json.get('email')) is None: # Check if the entered string is an email
        return make_response(jsonify({'message':Errors.EMAIL_VALIDATION,'status' : 401})), 400
    data = {}
    usersjson = {}
    user = Users.query.filter_by(email = request.json.get('email')).first() # Get the user form the DB using the email from the request.
    # Check there's a value in the user object and the status of the user is True.
    if user is not None:
        if user.status: 
            if len(request.json.get('password')) < 6: # Check if the password entered is greater than 6
                return make_response(jsonify({'message':Errors.INCORRECT_PASSWORD,'status' : 401})), 400
            isPassword =sha256_crypt.verify(request.json.get('password'), user.password) # Verify the hash password entered by the user
            device = Devices.query.filter_by(user_id = user.id).first() # Getting the device token for the user
            device_token = request.json.get('device_token') 
            device_type = request.json.get('device_type') 
            if isPassword is True:  # If the password verifies then continue
                userDetails = {
                    'id' : user.id,
                    'device_id' : device.id,
                    'name' : user.name,
                    'email' : user.email,
                    'is_login': True # Value is False if the user skips the login else True
                } # userDetails object would be used to create the access_token using JWT.
                # Creating data object to be returned in the response of the API
                data['name'] = user.name
                data['notification'] = device.notifications
                data['email'] = user.email
                data['gender'] = user.gender
                data['is_login'] = True
                data['FCM'] = device_token
                data['review'] = False
                if Review.query.filter_by(user = user.id).first():
                    data['review'] = True

                access_token = create_access_token(identity=userDetails,expires_delta=False) # Creating the access token using userDetails object
                finalData = {'info' : data,'message':Errors.LOGIN_MESSAGE,'access_token':access_token,'status' : 201}
                usersjson = json.dumps(finalData, indent=4, sort_keys=True)
                # Changing device_token with the token recieved in the login
                setattr(device, 'device_token', device_token)
                setattr(device, 'device_type', device_type)

                db.session.commit()
                return make_response(usersjson)
            else:
                return make_response(jsonify({'message':Errors.INCORRECT_PASSWORD,'status' : 401})), 400
        else:
            return make_response(jsonify({'message' : Errors.INVALID_CREDENTIALS,'status' : 401})), 400
    else:
        return make_response(jsonify({'message':Errors.INVALID_CREDENTIALS,'status' : 401})), 400


# This API is used when the used wants to skip the login and just want to use the app without login
# In skip login only the device token is stored in the Devices table for a user and there is no entry in the useres table
@app.route('/login/skip',methods = ['POST'])
def skipLogin():
    data = {}
    usersjson = {}
    # Get device token from the json request.
    device_token = request.json.get('device_token') 
    device_type = request.json.get('device_type') 
    # Check if the device token already exists in the table else store the token if it doesn't.
    if Devices.query.filter_by(device_token = device_token).first():
        device = Devices.query.filter_by(device_token = device_token).first()
    else:
        device = Devices(
            device_token = device_token,
            device_type = device_type,
            notifications = True
        )
        db.session.add(device)
        db.session.commit()
    userDetails = {
        'id' : 'Unknown',
        'device_id' : device.id,
        'is_login': False # Value is False if the user skips the login else True.
    }
    data['name'] = 'Unknown'
    data['notification'] = device.notifications
    data['email'] = 'Unknown'
    data['FCM'] = device_token
    data['gender'] = 'Unknown'
    data['review'] = False
    data['is_login'] = False
    
    
    access_token = create_access_token(identity=userDetails,expires_delta=False) # Creating the access token from the userDetails.
    finalData = {'info' : data,'message':Errors.LOGIN_MESSAGE,'access_token':access_token,'status' : 201}
    usersjson = json.dumps(finalData, indent=4, sort_keys=True)

    db.session.commit()
    return make_response(usersjson)





# This route is used to change the password if a user forgot his/her password.
# when hitting this API, an email is sent to the email entered during the request.
# Then from the URL that has been sent in the email a template opens and the user can enter new password
@app.route('/forgotPassword', methods = ['POST'])
def forgotPassword():
    if re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.json.get('email')) is None: # Check if the entered string is an email.
        return make_response(jsonify({'message':Errors.EMAIL_VALIDATION,'status' : 401})), 400
    if not Users.query.filter_by(email = request.json.get('email')).first(): # Check if user exists in the db, else return an error.
        return make_response(jsonify({'message':Errors.INVALID_CREDENTIALS,'status' : 401})), 400
    # Sending the Forgot password email to the user with the forgot template URL.
    forgot_password_mail(request.json.get('email'), Users.query.filter_by(email = request.json.get('email')).first().name)
    return make_response(jsonify({'message' : Errors.EMAIL_SUCCESSFUL, 'status' : 201}))
    


# This function is used to edit the user's details.
# Using the users id to get the users from the db and then a loop for every entry that 
# is required to be changed in the json content-type 
# The users_id is is get from the JWT.
@app.route('/users', methods=['PUT'])
@jwt_required
def editUser():
    try:
        data = {}
        userIdentity = get_jwt_identity()
        user = (Users.query.filter_by(id = userIdentity['id']).first()) # Getting the user from db.
        # Getting all the keys from the request json.
        for incoming in request.json:
            if 'name' in request.json and len(request.json.get('name')) > 50:
                return make_response(jsonify({'message':Errors.NAME_LENGTH_VALIDATION,'status' : 401})), 400
            setattr(user, incoming, request.json.get(incoming)) # adding the object to the db session using setattr() function.
        setattr(user, 'updated_at', datetime.datetime.utcnow()) # Changing the updated_at for that user in the table.
        db.session.commit()
        # Creating data object to be returned in the response.
        data['name'] = user.name
        data['email'] = user.email
        data['gender'] = user.gender
        data['is_login'] = True
        
        return make_response(jsonify({'info' : data, 'message':Errors.EDIT_USER_SUCCESS,'status' : 201, 'access_token' : request.headers.get('Authorization').replace('Bearer ',''), 'name' : user.name}))
    except (SQLAlchemyError, DBAPIError,IntegrityError) as e:
        return make_response(jsonify({'message':'Email is already registered. Please use another one.','status' : 401})), 400


# This route is used to get the users details of the single users.
# This API works for the get user with access_token.
# users_id is get from the JWT and the details of the users is returned in json.
@app.route('/users',methods = ['GET'])
@jwt_required
def getUser():
    userIdentity = get_jwt_identity() # Getting the user identity from the JWT.
    user = Users.query.filter_by(id = userIdentity['id']).first()
    if not user: # Return error if user does not exists in the db.
        return make_response(jsonify({'message' : Errors.UNKNOWN_USER, 'status' : 401})), 400
    usersjson = {}
    data = {}
    device = Devices.query.filter_by(user_id = user.id).first()
    # Creating the data object to be returned in the response for the API.
    data['id'] = (user.id).hex
    data['name'] = user.name
    data['email'] = user.email
    data['gender'] = user.gender
    data['is_login'] = userIdentity['is_login']
    data['notification'] = device.notifications
    data['FCM'] = device.device_token
    data['updated_at'] = str(user.updated_at)
    data['review'] = False

    finalData =  {'info': data, 'access_token' : request.headers.get('Authorization').replace('Bearer ',''), 'message' : 'success', 'status' : 201}
    usersjson = json.dumps(finalData, indent=4, sort_keys=True)
    return (usersjson)
    

# This route is used to change the password 
# And old_password and new_password are sent in the json content-type
@app.route('/changePassword', methods = ['POST'])
@jwt_required
def changePassword():
    userIdentity = get_jwt_identity() # Getting the user identity from the JWT.
    user = (Users.query.filter_by(id = userIdentity['id']).first())
    isPassword =sha256_crypt.verify(request.json.get('oldPassword'), user.password) # Verifying the old_password entered sent in the request with the pasword in the db.
    
     # Check if the password verifies, if it doesn't then return the appropriate errors else perform the action on the db.
    if isPassword is False:
        return make_response(jsonify({'message':Errors.INCORRECT_OLD_PASSWORD,'status' : 401}))
    elif len(request.json.get('newPassword')) < 6:
        return make_response(jsonify({'message':'New ' + Errors.PASSWORD_VALIDATION,'status' : 401}))
    elif isPassword:
        # Store the changed password and store it in the db.
        user.password = sha256_crypt.encrypt(request.json.get('newPassword'))
        db.session.commit()
        return make_response(jsonify({'message' : Errors.CHANGE_PASSWORD_SUCCESS, 'status' : 201, 'access_token' : request.headers.get('Authorization').replace('Bearer ','')}))

    else:
        return make_response(jsonify({'message' : Errors.INCORRECT_OLD_PASSWORD, 'status' : 401})), 400


# This API is called to change the status of the notifications of a device in the Devices table.
# In this function, the notification boolean is toggeled from the values stored before.
@app.route('/changeNotificationStatus', methods=['GET'])
@jwt_required
def changeNotificationStatus():
    try:
        userIdentity = get_jwt_identity()
        user = Devices.query.filter_by(id = userIdentity['device_id']).first()
        setattr(user, 'notifications', not user.notifications)
        db.session.commit()
        return make_response(jsonify({'notification' : user.notifications, 'message':Errors.EDIT_USER_SUCCESS,'status' : 201, 'access_token' : request.headers.get('Authorization').replace('Bearer ','')}))
    except (SQLAlchemyError, DBAPIError,IntegrityError) as e:
        print ('\n\n\n',e)


# This API is used to render the template for the forgot password form 
@app.route('/newPassword/<token>', methods = ['GET', 'POST'])
def forgotPasswordForm(token):
    form = ForgotForm() # Creating a form object of the ForgotForm WTF class 
    if form.Password.data and form.ConfirmPassword.data:
        # Validating inputs
        if form.Password.data != form.ConfirmPassword.data:
            flash('Passwords do not match.')
        else:
            payload = {
                    "password": form.Password.data
                }
            # Hitting the change password API form the template
            response = requests.post((app.config['API_HIT_URL']) + "/forgot/"+token, data=json.dumps(payload), headers = {'Content-Type' : 'application/json'}).json()
            if response['status'] == 201:
                    flash('Password changed successfully.')
            else:
                flash(response['message']) # Flashing response message on the template
    return render_template('forgot.html', title='Forgot Password', form=form)
