from flask import Blueprint
from flask_login import LoginManager

bp = Blueprint('auth', __name__, url_prefix='/auth')
login_manager = LoginManager()

from . import routes  