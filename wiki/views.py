"""

Views handlers here.

"""
import os
import shutil
from uuid import uuid4
from passlib.hash import sha256_crypt

from flask import session, flash, request, render_template, redirect, url_for, abort, escape, safe_join
from flask.json import load
from werkzeug.utils import secure_filename

from wiki import app
from wiki.helpers import login_check, access_check, dump_page, allowed_file, file_from_url


@app.route('/')
def main():
    """ Main page handler """
    return render_template('main.html', content='<h1>This is main page!</h1>')


@app.route('/login/', methods=['POST', 'GET'])
@login_check
def login():
    """ Login handler. Check password from user file and add <username> to session storage. """
    if request.method == 'POST':
        username = escape(request.form.get('username', None))
        password = request.form.get('password', None)
        if username is None or password is None:
            flash('Fill all fields!', 'error')
            return redirect(url_for('login'))
        try:
            user_file = safe_join(app.config['USERS_FOLDER'], username)
            with open(user_file, 'r') as uf:
                user_conf = load(uf)  # user_file on json format
            if not sha256_crypt.verify(password, user_conf['password']):  # check password
                flash('Wrong password!', 'error')
                return redirect(url_for('login'))
            else:
                flash('You successfully logged in!', 'info')
                session['username'] = request.form['username']
        except FileNotFoundError:
            flash('User not exist!', 'error')
            return redirect(url_for('login'))
        except Exception:
            abort(500)
        return redirect(request.args.get('next', url_for('main')))
    return render_template('login.html')


@app.route('/logout/')
def logout():
    """ Logout handler. Remove <username> from session storage. """
    if 'username' in session:
        session.pop('username', None)
        flash('You successfully logged out!', 'info')
    return redirect(url_for('main'))


@app.route('/page/<page_name>')
def page(page_name):
    """ Render page with content from page file """
    page_name = escape(page_name)
    if '@' in page_name:  # check for dump file
        page_path = safe_join(app.config['DUMPS_FOLDER'], page_name)
    else:
        page_path = safe_join(app.config['PAGES_FOLDER'], page_name)
    try:
        with open(page_path, 'r') as page_file:
            content = page_file.read()
        return render_template('page.html', context={'title': page_name, 'content': content})
    except FileNotFoundError:
        abort(404)
    except Exception:
        abort(500)


@app.route('/write/', methods=['POST', 'GET'])
@access_check
def write():
    """ Create new page with <page_name> filename in <PAGES_FOLDER> const. """
    if request.method == 'POST':
        page_name = escape(request.form.get('title', None))
        content = escape(request.form.get('content', None))
        create = request.form.get('create', '0')
        if page_name is None:
            flash('Enter correct title', 'error')
            return redirect(url_for('write'))
        page_path = safe_join(app.config['PAGES_FOLDER'], page_name)
        if create == '1' and os.path.isfile(page_path):
            flash('Page already exist with same name!', 'error')
        else:
            try:
                if create != '1':
                    dump_page(page_name)
                with open(page_path, 'w') as page_file:
                    page_file.write(content)
                flash('Success!', 'info')
                return redirect(url_for('page', page_name=page_name))
            except OSError:
                flash('Error writing to file!', 'error')
    return render_template('editor.html', context={})


@app.route('/write/<page_name>', methods=['POST', 'GET'])
@access_check
def edit(page_name):
    """ Edit existed page with <page_name> title """
    content = ''
    page_name = escape(page_name)
    page_path = safe_join(app.config['PAGES_FOLDER'], page_name)
    try:
        with open(page_path, 'r') as page_file:
            content = page_file.read()
    except OSError:
        abort(404)
    return render_template('editor.html', context={'title': page_name, 'content': content})


@app.route('/delete/', methods=['POST', 'GET'])
@access_check
def delete_page():
    """ Delete page with <title> filename. """
    if request.method == 'POST':
        try:
            page_name = escape(request.form.get('title', None))
            if page_name is None:
                raise OSError  # hrr
            dump_page(page_name)
            os.remove(safe_join(app.config['PAGES_FOLDER'], page_name))
            flash('Success!', 'info')
        except OSError:
            flash('That page does not exist!', 'error')
    return redirect(url_for('main'))


@app.route('/restore/', methods=['POST'])
@access_check
def restore():  # TODO: test this; FIXME: error 405
    """ Restore page from dump storage """
    page_name = escape(request.form.get('title', None))
    timestamp = request.form.get('time', None, type=int)
    if page_name is None or timestamp is None:
        flash('Fill all fields!', 'error')
        return redirect(url_for('main'))
    page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
    dump_file = safe_join(app.config['DUMPS_FOLDER'], page_name + '@' + timestamp)  # TODO: TEST!!!
    try:
        shutil.copyfile(dump_file, page_file)
        flash('Success!', 'info')
    except OSError:
        flash('Can not restore this page!', 'error')
    return redirect(url_for('main'))


@app.route('/upload/', methods=['GET', 'POST'])
@access_check
def upload():
    """ File uploading handler. """
    url = request.args.get('url', None)
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(safe_join(app.config['UPLOAD_FOLDER'], filename))
            flash('File ' + filename + ' was uploaded!', 'info')
        else:
            flash('File was not uploaded!', 'error')
    if url is not None:
        file = file_from_url(url)
        if file and allowed_file(file['name']):
            file_name = secure_filename(file['name'])
            file_path = safe_join(app.config['UPLOAD_FOLDER'], file_name)
            with open(file_path, 'wb') as f:
                f.write(file['content'])
            flash('File ' + file_name + ' was uploaded!', 'info')
        else:
            flash('Can not download file!', 'error')
    return render_template('upload.html', context={})


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(403)
def access_denied(error):
    return render_template('403.html'), 403


@app.errorhandler(500)
def something_wrong(error):
    return render_template('500.html'), 500
