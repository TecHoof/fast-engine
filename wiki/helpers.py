"""

Some helpful function and decorators

"""
import os
import shutil
import time
import requests
from functools import wraps
from passlib.hash import sha256_crypt

from flask import session, flash, redirect, url_for, abort, g, request, safe_join
from flask.json import dump, load

from wiki import app


def login_check(func):
    """ Check for active login session """
    @wraps(func)
    def wrapper():
        if 'username' in session:
            flash('You are already logged in!', 'info')
            return redirect(url_for('main'))
        return func()
    return wrapper


def access_check(func):
    """ Check for user authorization """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            g.login_back = request.path
            abort(401)
        return func(*args, **kwargs)
    return wrapper


def dump_page(page_name=None):
    """ Backup current page to <dumps_path> directory """
    dumps_list = show_dumps(page_name)
    if len(dumps_list) > 9:
        os.remove(app.config['DUMPS_FOLDER'] + page_name + '@' + dumps_list[0])
    page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
    stamp_file = safe_join(app.config['DUMPS_FOLDER'], page_name + '@' + str(int(time.time())))  # hrr
    shutil.copyfile(page_file, stamp_file)


def show_dumps(page_name=None):
    """ Return list of dumped pages """
    dumps_list = []
    for root, dirs, files in os.walk(app.config['DUMPS_FOLDER']):
        for dump_name in files:
            dump_name = dump_name.split('@')
            if page_name in dump_name:
                dumps_list.append(dump_name[1])  # timestamp
    return sorted(dumps_list)


def allowed_file(filename=None):
    """ Check for allowed extension of file"""
    return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


def file_from_url(url=None):
    """ Download file from given url and return dictionary"""
    file = {}
    r = requests.get(url)
    if r.status_code == 200:
        file['name'] = url.rsplit('/', 1)[1]
        file['ext'] = file['name'].rsplit('.', 1)[1]
        file['content'] = r.content
    return file


def settings_write(name=None, key=None, value=None):
    """ Write to settings file """
    file = safe_join(app.config['SETTINGS_FOLDER'], name + '.json')
    content = settings_read(name)
    content[key] = value
    with open(file, 'w') as f:
        dump(content, f)


def settings_read(name=None):
    """ Read from settings file """
    file = safe_join(app.config['SETTINGS_FOLDER'], name + '.json')
    try:
        with open(file, 'r') as f:
            content = load(f)
    except FileNotFoundError:
        content = {}
    return content


def create_user(username=None, password=None):
    """ Create user """
    user_file = safe_join(app.config['USERS_PATH'], username)
    password = sha256_crypt.encrypt(password)
    with open(user_file, 'x') as f:
        dump({'password': password}, f)
    settings_write(username, 'create', time.time())
