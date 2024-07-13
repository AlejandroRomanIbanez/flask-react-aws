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
