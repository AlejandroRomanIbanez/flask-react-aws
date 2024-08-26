# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.realpath(__file__))


class BaseConfig:

    load_dotenv()
    COGNITO_REGION = os.getenv("COGNITO_REGION")
    COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
    COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
    COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")
    COGNITO_REDIRECT_URI = os.getenv("COGNITO_REDIRECT_URI")
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    SALESFORCE_CLIENT_ID = os.getenv("SALESFORCE_CLIENT_ID")
    SALESFORCE_CLIENT_SECRET = os.getenv("SALESFORCE_CLIENT_SECRET")
    SALESFORCE_REDIRECT_URI = os.getenv("SALESFORCE_REDIRECT_URI")
