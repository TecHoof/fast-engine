"""

Application configuration

"""
from flask import Flask

app = Flask(__name__)
app.static_folder = app.root_path + '/../static'
app.config.update(
    DEBUG=True,  # FIXME: debug off on production
    SECRET_KEY='Every pony is the best pony!',  # FIXME: make you own secret key
    SESSION_COOKIE_NAME='library',
    SITE_TITLE='Flask Wiki',  # FIXME: change it!
    USERS_PATH=app.root_path + '/users/',
    PAGES_PATH=app.static_folder + '/pages/',
    DUMPS_PATH=app.static_folder + '/dumps/',
    SUPERADMIN_LOGIN='Braunly',
    SUPERADMIN_PASSWORD='123',
)

import wiki.views  # sorry for that x)
