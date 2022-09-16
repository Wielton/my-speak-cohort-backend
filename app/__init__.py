from flask import Flask

app = Flask(__name__)

from endpoints import user_register, user_login, comments