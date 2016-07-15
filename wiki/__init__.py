"""

Application configuration

"""
from flask import Flask

app = Flask(__name__, static_folder='../static')

# YOUR FRAMEWORK SETTINGS HERE
DEBUG = True
SECRET_KEY = 'Every pony is the best pony!'
SESSION_COOKIE_NAME = 'library'
SITE_TITLE = 'wiki Engine'
USERS_FOLDER = app.root_path + '/users/'
SETTINGS_FOLDER = app.root_path + '/settings/'
FEEDBACK_FOLDER = app.root_path + '/feedback/'
PAGES_FOLDER = app.static_folder + '/pages/'
DUMPS_FOLDER = app.static_folder + '/dumps/'
UPLOAD_FOLDER = app.static_folder + '/files/'
SUPERADMIN_LOGIN = 'Braunly'
ALLOWED_EXTENSIONS = ['apng', 'png', 'jpg', 'jpeg', 'gif']
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app.config.update(
    DEBUG=DEBUG,
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_NAME=SESSION_COOKIE_NAME,
    SITE_TITLE=SITE_TITLE,
    USERS_FOLDER=USERS_FOLDER,
    PAGES_FOLDER=PAGES_FOLDER,
    DUMPS_FOLDER=DUMPS_FOLDER,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    SETTINGS_FOLDER=SETTINGS_FOLDER,
    FEEDBACK_FOLDER=FEEDBACK_FOLDER,
    SUPERADMIN_LOGIN=SUPERADMIN_LOGIN,
    ALLOWED_EXTENSIONS=ALLOWED_EXTENSIONS,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
)

import wiki.views  # sorry for that x)
