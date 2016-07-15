"""

Views handlers here.

"""
import os
import shutil
import time
import datetime
from passlib.hash import sha256_crypt

from flask import session, flash, request, render_template, redirect, url_for, abort, escape, safe_join
from flask.json import load
from werkzeug.utils import secure_filename

from wiki import app
from wiki.helpers import login_check, access_check, dump_page, show_dumps, allowed_file, file_from_url, settings_read, \
    settings_write, show_users, create_user


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
        if not username or not password:
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
                session['username'] = username
                settings_write(username, 'last_login', int(time.time()))
        except FileNotFoundError:
            flash('User not exist!', 'error')
            return redirect(url_for('login'))
        except Exception:  # FIXME!!!
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
    if not page_name:
        abort(404)
    page_name = escape(page_name)
    content = ''
    settings = settings_read(page_name)
    settings['last_change'] = datetime.datetime.fromtimestamp(settings['last_change']).strftime('%d-%m-%Y %H:%M')
    if '@' in page_name:  # check for dump file
        page_file = safe_join(app.config['DUMPS_FOLDER'], page_name)
    else:
        page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
    try:
        with open(page_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        abort(404)
    except Exception:
        abort(500)
    return render_template('page.html', context={'title': page_name, 'content': content, 'settings': settings})


@app.route('/write/', methods=['POST', 'GET'])
@access_check
def write():
    """ Create new page with <page_name> filename in <PAGES_FOLDER> const. """
    if request.method == 'POST':
        page_name = escape(request.form.get('title', None))
        content = escape(request.form.get('content', None))
        create = request.form.get('create', '0')  # default zero; TODO: rewrite this
        if not page_name:
            flash('Enter correct title', 'error')
            return redirect(url_for('write'))
        page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
        if create == '1' and os.path.isfile(page_file):
            flash('Page already exist with same name!', 'error')
        else:
            try:
                if create != '1':
                    dump_page(page_name)
                with open(page_file, 'w') as f:
                    f.write(content)
                settings_write(page_name, 'last_author', session['username'])
                settings_write(page_name, 'last_change', int(time.time()))
                flash('Success!', 'info')
                return redirect(url_for('page', page_name=page_name))
            except OSError:
                flash('Can not save page!', 'error')
    return render_template('editor.html', context={})


@app.route('/write/<page_name>', methods=['POST', 'GET'])
@access_check
def edit(page_name):
    """ Edit existed page with <page_name> title """
    content = ''
    page_name = escape(page_name)
    page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
    try:
        with open(page_file, 'r') as f:
            content = f.read()
    except OSError:
        abort(404)
    return render_template('editor.html', context={'title': page_name, 'content': content})


@app.route('/delete/<page_name>', methods=['GET'])
@access_check
def delete_page(page_name):
    """ Delete page with <page_name> filename. """
    if not page_name:
        abort(404)
    if '@' in page_name:
        page_file = safe_join(app.config['DUMPS_FOLDER'], page_name)
    else:
        page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
        dump_page(page_name)
    try:
        os.remove(page_file)
        settings_write(page_name, 'deleted_by', session['username'])
        settings_write(page_name, 'deleted_on', int(time.time()))
        flash('Success!', 'info')
    except OSError:
        flash('That page does not exist!', 'error')
    return redirect(url_for('main'))


@app.route('/restore/<dump_name>', methods=['GET'])
@access_check
def restore(dump_name):
    """ Restore page from dump storage """
    if not dump_name:
        abort(404)
    if '@' in dump_name:
        dump = dump_name.split('@')
        page_file = safe_join(app.config['PAGES_FOLDER'], dump[0])
        dump_file = safe_join(app.config['DUMPS_FOLDER'], dump[0] + '@' + dump[1])
        try:
            dump_page(dump[0])
            shutil.copyfile(dump_file, page_file)
            flash('Success!', 'info')
        except OSError:
            flash('Can not restore this page!', 'error')
        finally:
            return redirect(url_for('page', page_name=dump[0]))
    dumps = []
    timestamps = show_dumps(dump_name)
    for timestamp in timestamps:
        hr_time = datetime.datetime.fromtimestamp(int(timestamp)).strftime('%d-%m-%Y %H:%M')
        dump = {'timestamp': timestamp, 'hr_time': hr_time}
        dumps.append(dump)
    if not dumps:
        flash('Dumps for this page not found!', 'error')
        return redirect(url_for('page', page_name=dump_name))
    return render_template('restore.html', context={"title": dump_name, "dumps": dumps})


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


@app.route('/feedback/<page_name>', methods=['GET', 'POST'])
def feedback(page_name):
    """ Write user feedback to file. """
    if page_name == '':
        abort(404)
    if request.method == 'POST':
        name = escape(request.form.get('name', ''))
        email = escape(request.form.get('email', ''))
        content = request.form.get('content', '')
        timestamp = str(int(time.time()))
        file = safe_join(app.config['FEEDBACK_FOLDER'], '%'.join([page_name, name, email, timestamp]))
        if not name or not email or not content:
            flash('Please, fill all fields!', 'error')
            return redirect(url_for('feedback', page_name=page_name))
        with open(file, 'w') as f:
            f.write(content)
        flash('Thank you for feedback.', 'info')
        return redirect(url_for('page', page_name=page_name))
    return render_template('feedback.html', context={"title":page_name})


@app.route('/admin/', methods=['GET', 'POST'])
@access_check
def admin():
    """ Admin panel handler. """
    if session['username'] != app.config['SUPERADMIN_LOGIN']:
        abort(403)
    if request.method == 'POST':
        if request.form.get('form') == 'create_user':
            username = escape(request.form.get('username', ''))
            password = request.form.get('password', '')
            if not username or not password:
                flash('Fill all fields!', 'error')
                return redirect(url_for('admin'))
            try:
                create_user(username, password)
                flash('Success!', 'info')
            except FileExistsError:
                flash('User exist!', 'error')
            except OSError:
                flash('Can not create new user!', 'error')
            except Exception:
                abort(500)
            finally:
                return redirect(url_for('admin'))
    return render_template('admin.html', context={"users": show_users()})


@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html'), 401


@app.errorhandler(403)
def access_denied(error):
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def something_wrong(error):
    return render_template('500.html'), 500
