# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from functools import wraps
from flask import request, redirect, make_response, jsonify, session
from flask_restx import Api, Resource, fields
from . import mongo
from .models import Users
from dotenv import load_dotenv
from .config import BaseConfig
from datetime import datetime, timedelta
import os
import base64
import hashlib
import requests
import boto3
import json
import string
import random

load_dotenv()
COGNITO_APP_CLIENT_ID = BaseConfig.COGNITO_APP_CLIENT_ID
COGNITO_REGION = BaseConfig.COGNITO_REGION
COGNITO_DOMAIN = BaseConfig.COGNITO_DOMAIN
COGNITO_USER_POOL_ID = BaseConfig.COGNITO_USER_POOL_ID
COGNITO_REDIRECT_URI = BaseConfig.COGNITO_REDIRECT_URI
GOOGLE_CLIENT_ID = BaseConfig.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = BaseConfig.GOOGLE_CLIENT_SECRET
SALESFORCE_CLIENT_ID = BaseConfig.SALESFORCE_CLIENT_ID
SALESFORCE_CLIENT_SECRET = BaseConfig.SALESFORCE_CLIENT_SECRET
SALESFORCE_REDIRECT_URI = BaseConfig.SALESFORCE_REDIRECT_URI

cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)


rest_api = Api(version="1.0", title="Users API")


signup_model = rest_api.model('SignUpModel', {
    "username": fields.String(required=True, min_length=2, max_length=32),
    "email": fields.String(required=True, min_length=4, max_length=64),
    "password": fields.String(required=True, min_length=4, max_length=16)
})

login_model = rest_api.model('LoginModel', {
    "email": fields.String(required=True, min_length=4, max_length=64),
    "password": fields.String(required=True, min_length=4, max_length=16)
})

user_edit_model = rest_api.model('UserEditModel', {
    "userID": fields.String(required=True, min_length=1, max_length=32),
    "username": fields.String(required=True, min_length=2, max_length=32),
    "email": fields.String(required=True, min_length=4, max_length=64)
})


def serialize_user(user):
    """Helper function to convert ObjectId and datetime to JSON serializable format."""
    if '_id' in user:
        user['_id'] = str(user['_id'])
    for key, value in user.items():
        if isinstance(value, datetime):
            user[key] = value.isoformat()
    return user


def refresh_token(refresh_token):
    try:
        token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"
        token_data = {
            'grant_type': 'refresh_token',
            'client_id': COGNITO_APP_CLIENT_ID,
            'refresh_token': refresh_token,
        }
        token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        token_response = requests.post(token_url, data=token_data, headers=token_headers)
        token_json = token_response.json()

        if 'error' in token_json:
            return None, token_json['error']

        return token_json, None
    except Exception as e:
        return None, str(e)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get("Authorization")
        token = token.replace("Bearer ", "").strip()
        if not token:
            return {"success": False, "msg": "Valid JWT token is missing"}, 400

        try:
            user_info = cognito_client.get_user(AccessToken=token)
            current_user_email = None

            for attribute in user_info['UserAttributes']:
                if attribute['Name'] == 'email':
                    current_user_email = attribute['Value']
                    break
            if not current_user_email:
                return {"success": False, "msg": "User not found"}, 400

            current_user = Users.get_by_email(current_user_email)
            if not current_user:
                return {"success": False, "msg": "User not found in database"}, 400

        except cognito_client.exceptions.NotAuthorizedException:
            if request.endpoint == 'logout' or 'logout' in request.path:
                print("Token is invalid or expired, but proceeding with logout.")
                return f(None, *args, **kwargs)
            else:
                refresh_token_value = request.cookies.get('refresh_token')
                if not refresh_token_value:
                    return {"success": False, "msg": "Token is invalid or expired"}, 400

            token_json, error = refresh_token(refresh_token_value)
            if error:
                return {"success": False, "msg": "Token refresh failed: " + error}, 400

            access_token = token_json['access_token']
            id_token = token_json['id_token']
            response = make_response({"success": True, "access_token": access_token, "id_token": id_token})
            response.set_cookie('access_token', access_token, httponly=True, secure=True)
            response.set_cookie('id_token', id_token, httponly=True, secure=True)
            return response

        return f(current_user, *args, **kwargs)
    return decorator


@rest_api.route('/api/users/register')
class Register(Resource):
    """
       Creates a new user by taking 'signup_model' input
    """
    @rest_api.expect(signup_model, validate=True)
    def post(self):
        req_data = request.get_json()

        _username = req_data.get("username")
        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = mongo.db.users.find_one({"email": _email})
        if user_exists:
            return {"success": False, "msg": "Email already taken"}, 400
        try:
            cognito_client.sign_up(
                ClientId=COGNITO_APP_CLIENT_ID,
                Username=_username,
                Password=_password,
                UserAttributes=[
                    {'Name': 'email', 'Value': _email}
                ]
            )
            new_user = Users(username=_username, email=_email)
            new_user.set_password(_password)
            new_user.save()
            return {"success": True, "msg": "User registered successfully"}, 200

        except Exception as e:
            return {"success": False, "msg": str(e)}, 500


@rest_api.route('/api/users/login')
class Login(Resource):
    """
       Login user by taking 'login_model' input and return JWT token
    """

    @rest_api.expect(login_model, validate=True)
    def post(self):
        req_data = request.get_json()

        _email = req_data.get("email")
        _password = req_data.get("password")

        user_exists = mongo.db.users.find_one({"email": _email})

        if not user_exists:
            return {"success": False, "msg": "This email does not exist."}, 400

        try:
            response = cognito_client.initiate_auth(
                ClientId=COGNITO_APP_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': user_exists['username'],
                    'PASSWORD': _password
                }
            )
            token = response['AuthenticationResult']['AccessToken']
            user = Users(**user_exists)
            return {"success": True, "token": token, "user": user.to_json()}, 200
        except cognito_client.exceptions.NotAuthorizedException:
            return {"success": False, "msg": "Wrong credentials."}, 400
        except Exception as e:
            return {"success": False, "msg": str(e)}, 500


@rest_api.route('/api/users/logout')
class LogoutUser(Resource):
    @token_required
    def post(self, current_user):
        try:
            token = request.headers.get("Authorization")
            if not token:
                return {"success": False, "msg": "Authorization header is missing"}, 401

            token = token.replace("Bearer ", "").strip()
            print(f"Received token: {token}")
            if not token:
                return {"success": False, "msg": "Valid JWT token is missing"}, 400

            try:
                cognito_client.global_sign_out(AccessToken=token)
                return {"success": True, "msg": "Logged out successfully"}, 200

            except cognito_client.exceptions.NotAuthorizedException:
                # This error occurs if the token is already invalid or expired
                return {"success": False, "msg": "Token is invalid or expired. You have been logged out."}, 400

        except cognito_client.exceptions.InvalidParameterException as e:
            return {"success": False, "msg": f"An error occurred: {str(e)}"}, 400
        except Exception as e:
            return {"success": False, "msg": f"An error occurred: {str(e)}"}, 500


@rest_api.route('/api/users/callback', methods=['GET'])
class OAuthCallback(Resource):
    def get(self):
        code = request.args.get('code')
        if not code:
            return {"success": False, "msg": "Authorization code not provided"}, 400

        try:
            token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"
            token_data = {
                'grant_type': 'authorization_code',
                'client_id': COGNITO_APP_CLIENT_ID,
                'code': code,
                'redirect_uri': COGNITO_REDIRECT_URI,
            }
            token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            token_response = requests.post(token_url, data=token_data, headers=token_headers)
            token_json = token_response.json()

            if 'error' in token_json:
                return {"success": False, "msg": token_json['error']}, 400

            access_token = token_json.get('access_token')
            id_token = token_json.get('id_token')
            refresh_token = token_json.get('refresh_token')

            user_info_url = f"https://{COGNITO_DOMAIN}/oauth2/userInfo"
            user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
            user_info = user_info_response.json()

            email = user_info.get('email')
            if not email:
                return {"success": False, "msg": "Email not found in user info"}, 400

            user = mongo.db.users.find_one({"email": email})
            if not user:
                # Create a new user if it doesn't exist
                user_data = {
                    "username": user_info.get('username'),
                    "email": email,
                    "created_at": datetime.utcnow(),
                }
                mongo.db.users.insert_one(user_data)
                user = user_data  # Newly created user

            user_serialized = serialize_user(user)

            # Convert the user data to JSON
            user_json = json.dumps(user_serialized)

            return {
                "success": True,
                "access_token": access_token,
                "id_token": id_token,
                "refresh_token": refresh_token,
                "user": user_json
            }, 200
        except Exception as e:
            return {"success": False, "msg": str(e)}, 500

def generate_session_token():
    return base64.urlsafe_b64encode(os.urandom(24)).rstrip(b'=').decode('utf-8')

def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')


def generate_strong_password(length=12):
    # Ensure the password meets Cognito's policy: at least one uppercase, one lowercase, one digit, and one special character
    password_characters = (
        string.ascii_letters + string.digits + string.punctuation
    )
    while True:
        password = ''.join(random.choice(password_characters) for i in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password

@rest_api.route('/api/users/salesforce/login')
class SalesforceLogin(Resource):
    def get(self):
        # Generate code verifier and challenge
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        # Debugging output
        print("Generated Code Verifier:", code_verifier)

        # Return the code_verifier and auth URL to the frontend
        auth_url = (
            f"https://login.salesforce.com/services/oauth2/authorize?response_type=code"
            f"&client_id={SALESFORCE_CLIENT_ID}"
            f"&redirect_uri={SALESFORCE_REDIRECT_URI}"
            f"&scope=openid email profile offline_access"
            f"&code_challenge={code_challenge}&code_challenge_method=S256"
        )

        return jsonify({"auth_url": auth_url, "code_verifier": code_verifier})


@rest_api.route('/api/users/salesforce/callback', methods=['GET'])
class SalesforceOauthCallback(Resource):
    def get(self):
        try:
            # Retrieve the authorization code and code_verifier from the request
            code = request.args.get('code')
            code_verifier = request.args.get('code_verifier')

            print("Authorization Code:", code)
            print("Code Verifier:", code_verifier)

            if not code or not code_verifier:
                return jsonify({"success": False, "msg": "Authorization code or code verifier not provided"}), 400

            # Exchange the authorization code for an access token
            token_url = "https://login.salesforce.com/services/oauth2/token"
            token_data = {
                'grant_type': 'authorization_code',
                'client_id': SALESFORCE_CLIENT_ID,
                'client_secret': SALESFORCE_CLIENT_SECRET,
                'code': code,
                'redirect_uri': SALESFORCE_REDIRECT_URI,
                'code_verifier': code_verifier
            }
            token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            token_response = requests.post(token_url, data=token_data, headers=token_headers)
            token_json = token_response.json()

            if 'error' in token_json:
                return jsonify({"success": False, "msg": token_json['error']}), 400

            access_token = token_json.get('access_token')
            refresh_token = token_json.get('refresh_token')
            instance_url = token_json.get('instance_url')

            # Retrieve user information from Salesforce
            user_info_url = f"{instance_url}/services/oauth2/userinfo"
            user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
            user_info = user_info_response.json()
            user_data = {
                "username": user_info.get('username'),
                "email": user_info.get('email'),
                "created_at": datetime.utcnow(),
            }

            print("User Info JSON:", user_info)

            email = user_data.get('email')
            if not email:
                return jsonify({"success": False, "msg": "Email not found in user info"}), 400

            existing_user = mongo.db.users.find_one({"email": email})

            if not existing_user:
                username = f"salesforce_{user_info.get('user_id')}"
                user_data = {
                    "username": username,
                    "email": email,
                    "created_at": datetime.utcnow(),
                }
                mongo.db.users.insert_one(user_data)
                user = user_data

                try:
                    cognito_client.sign_up(
                        ClientId=BaseConfig.COGNITO_APP_CLIENT_ID,
                        Username=username,
                        Password=generate_strong_password(),
                        UserAttributes=[
                            {'Name': 'email', 'Value': email},
                        ]
                    )
                    print(f"User {username} created in Cognito.")

                except cognito_client.exceptions.UsernameExistsException:
                    print(f"User {username} already exists in Cognito.")
                except Exception as e:
                    print(f"Failed to create user in Cognito: {str(e)}")
            else:
                mongo.db.users.update_one(
                    {"email": email},
                    {"$set": {"user_info": user_info, "provider": "salesforce"}}
                )
                user = existing_user


            # Serialize the user data for JSON response
            user_serialized = serialize_user(user)

            # Prepare the response as an object with tokens and user info
            response_data = {
                "success": True,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": user_serialized
            }
            print("Response Data:", response_data)

            # Return the JSON response
            return jsonify(response_data)

        except Exception as e:
            # Log the full traceback and error message
            import traceback
            traceback.print_exc()
            print("Error occurred:", str(e))
            return jsonify({"success": False, "msg": str(e)}), 500

