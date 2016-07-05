"""

Some helpful function and decorators

"""
import os
import shutil
import time
from functools import wraps

from flask import session, flash, redirect, url_for, abort, g, request, safe_join

from wiki import app


def login_check(func):
    """ Check for user authorization """
    @wraps(func)
    def wrapper():
        if 'username' in session:
            flash('You are already logged in!', 'info')
            return redirect(url_for('main'))
        return func()
    return wrapper


def access_check(func):
    """ Check for access to that handler """
    @wraps(func)
    def wrapper():
        if 'username' not in session:
            g.login_back = request.path
            abort(403)
        return func()
    return wrapper


def dump_page(page_name):  # FIXME
    """ Backup current page to <dumps_path> directory """
    dumps_list = show_dumps(page_name)
    print(dumps_list)
    if len(dumps_list) > 9:
        os.remove(app.config['DUMPS_PATH'] + page_name + '@' + dumps_list[0])
    page_file = safe_join(app.config['PAGES_PATH'], page_name)
    stamp_file = safe_join(app.config['DUMPS_PATH'], page_name + '@' + str(int(time.time())))  # hrr
    shutil.copyfile(page_file, stamp_file)


def show_dumps(page_name):  # TODO: test this
    dumps_list = []
    for root, dirs, files in os.walk(app.config['DUMPS_PATH']):
        for dump_name in files:
            dump_name = dump_name.split('@')
            if page_name in dump_name:
                dumps_list.append(dump_name[1])  # timestamp
    return sorted(dumps_list)
