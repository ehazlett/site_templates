import os
import logging
import sys
sys.path.append('./')
try:
    import simplejson as json
except ImportError:
    import json

DEBUG = True
VERSION = '0.1'
SECRET_KEY = "yoursupersecretkey"
# redis
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None
REDIS_QUEUE_KEY = 'tasks:queue'
REDIS_QUEUE_KEY_TTL = 86400

