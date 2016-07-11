"""

Application configuration

"""
from flask import Flask
# TODO: make constants
app = Flask(__name__)
app.static_folder = app.root_path + '/../static'
app.config.update(
    DEBUG=True,
    SECRET_KEY='Every pony is the best pony!',
    SESSION_COOKIE_NAME='library',
    SITE_TITLE='wiki Engine',
    USERS_FOLDER=app.root_path + '/users/',
    PAGES_FOLDER=app.static_folder + '/pages/',
    DUMPS_FOLDER=app.static_folder + '/dumps/',
    UPLOAD_FOLDER=app.static_folder + '/files/',
    SETTINGS_FOLDER=app.root_path + '/settings/',
    SUPERADMIN_LOGIN='Braunly',
    SUPERADMIN_PASSWORD='123',
    ALLOWED_EXTENSIONS=['apng', 'png', 'jpg', 'jpeg', 'gif'],
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

import wiki.views  # sorry for that x)
