# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os, json

from flask import Flask
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv


load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
mongo = MongoClient(MONGO_URI)


def create_app():
    app = Flask(__name__)
    app.config.from_object('api.config.BaseConfig')
    CORS(app)

    from .routes import rest_api

    rest_api.init_app(app)
    return app


def after_request(response):
    if int(response.status_code) >= 400:
        try:
            response_data = json.loads(response.get_data())
            if "errors" in response_data:
                response_data = {"success": False, "msg": list(response_data["errors"].items())[0][1]}
                response.set_data(json.dumps(response_data))
        except json.JSONDecodeError as e:
            # Handle JSON decode errors gracefully
            response_data = {"success": False, "msg": "Error: Invalid JSON response"}
            response.set_data(json.dumps(response_data))
        except Exception as e:
            # Handle other exceptions here
            print(f"Error processing response: {str(e)}")
            response_data = {"success": False, "msg": "Error processing response"}

    return response
