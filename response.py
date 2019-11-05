# Copyright (c) * Raman
import datetime,os

# This Error class returns the errors and responses in the different API hits.
class Errors(object):
    UNKNOWN_ERROR = 'Oops! Something went wrong.'
    UNKNOWN_USER = 'Sorry! User with supplied input does not exist.'
    PERMISSION_DENIED = 'This operation is not permitted. Please contact webmaster.'
    EMAIL_SUCCESSFUL = 'Email sent successfully.'


    # User Auth
    EMAIL_ALREADY_REGISTERED = 'Email already exists. Please use a unique email address.'
    PASSWORD_VALIDATION = 'Password length must be greater than 6.'
    LOGIN_MESSAGE = 'Logged in successfully.'
    INCORRECT_PASSWORD = 'Incorrect Password. Please try again.'
    INVALID_CREDENTIALS = 'No match found! Please enter valid credentials.'
    EMAIL_VALIDATION = 'Enter a valid email address.'
    REGISTERATION_SECCESS = 'User registered successfully.'
    NAME_LENGTH_VALIDATION = 'Name length must be less than 50.'


    # User
    CHANGE_PASSWORD_SUCCESS = 'Password changed successfully.'
    EDIT_USER_SUCCESS = 'Profile updated successfully.'
    USER_DELETION_MESSAGE = 'User deleted successfully.'
    INCORRECT_OLD_PASSWORD = 'Please enter correct old password.'
    INVALID_IMAGE_ERROR = 'Image type must be jpg, jpeg, png, or gif.'