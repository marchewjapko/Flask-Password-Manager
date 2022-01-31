import logging
import sys
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/home/joe/Desktop/Flask/Flask_Password_Manager')
from main import app as application
application.secret_key = '123123!!!SecretKey'