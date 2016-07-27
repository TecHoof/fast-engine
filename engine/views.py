"""

Views handlers here.

"""
import os
import shutil
import time
import datetime
from passlib.hash import sha256_crypt

from flask import session, flash, request, render_template, redirect, url_for, abort, escape, safe_join
from flask.json import load, dump
from werkzeug.utils import secure_filename

from engine import app
from engine.helpers import login_check, access_check, dump_page, show_dumps, allowed_file, file_from_url, settings_read, \
    settings_write, Admin, show_feedback, show_files, show_pages, show_feedback_all


@app.route('/')
def main():
    """ Main page handler """
    if app.config['FIRST_START']:
        return redirect(url_for('install'))
    if app.config['MAINTENANCE']:
        return render_template('maintenance.html')
    return render_template('main.html', content='<h1>This is main page!</h1>')


@app.route('/install/', methods=['GET', 'POST'])
def install():
    """ Installation handler """
    if not app.config['FIRST_START']:  # can access only with FIRST_START == True
        abort(403)
    if request.method == 'POST':
        secret_key = request.form.get('secret_key', None)
        site_title = request.form.get('site_title', None)
        admin_login = request.form.get('admin_login', None)
        admin_password = request.form.get('admin_password', None)
        if not secret_key or not site_title or not admin_login or not admin_password:
            flash('Fill all fields!', 'error')
            return redirect(url_for('install'))
        elif '.' in admin_login or '/' in admin_login:
            flash('Invalid admin login!', 'error')
            return redirect(url_for('install'))
        config = {
            "SECRET_KEY": secret_key,
            "SITE_TITLE": site_title,
            "USERS_FOLDER": app.root_path + '/users/',
            "SETTINGS_FOLDER": app.root_path + '/settings/',
            "FEEDBACK_FOLDER": app.static_folder + '/feedback/',
            "PAGES_FOLDER": app.static_folder + '/pages/',
            "DUMPS_FOLDER": app.static_folder + '/dumps/',
            "UPLOAD_FOLDER": app.static_folder + '/files/',
            "ALLOWED_EXTENSIONS": ["apng", "png", "jpg", "jpeg", "gif"],
            "MAX_CONTENT_LENGTH": 16777216,
            "ADMIN_LOGIN": admin_login,
            "SESSION_COOKIE_NAME": "library",
            "FIRST_START": False,
            "MAINTENANCE": False,
            "DEBUG": False,
            "VERSION": "0.8.1",
        }
        app.config.update(config)
        try:
            with open(safe_join(app.root_path, 'config.json'), 'w') as f:
                dump(config, f)
            Admin.create_user(admin_login, admin_password)
            flash('Success!', 'info')
        except Exception:
            abort(500)
        return redirect(url_for('main'))
    return render_template('install.html')


@app.route('/login/', methods=['POST', 'GET'])
@login_check
def login():
    """ Login handler. Check password from user file and add <username> to session storage. """
    if request.method == 'POST':
        username = escape(request.form.get('username', None))
        password = request.form.get('password', None)
        next_url = request.args.get('next', url_for('main'))
        if not username or not password:
            flash('Fill all fields!', 'error')
            return redirect(url_for('login', next=next_url))
        try:
            user_file = safe_join(app.config['USERS_FOLDER'], username)
            with open(user_file, 'r') as uf:
                user_conf = load(uf)  # user_file on json format
            if not sha256_crypt.verify(password, user_conf['password']):  # check password
                flash('Wrong password!', 'error')
                return redirect(url_for('login', next=next_url))
            else:
                flash('You successfully logged in!', 'info')
                session['username'] = username
                settings_write(username, 'last_login', int(time.time()))
        except FileNotFoundError:
            flash('User not exist!', 'error')
            return redirect(url_for('login', next=next_url))
        except Exception:
            abort(500)
        return redirect(next_url)
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
    if not page_name or page_name == '.gitignore' or '.' in page_name or '/' in page_name:
        abort(404)
    page_name = escape(page_name)
    content = ''
    settings = []
    if '@' in page_name:
        page_file = safe_join(app.config['DUMPS_FOLDER'], page_name)
    else:
        page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
        try:
            settings = settings_read(page_name)
            settings['last_change'] = datetime.datetime.fromtimestamp(settings['last_change']).strftime('%d-%m-%Y %H:%M')
        except KeyError:
            flash('Please, use editor to create new page!', 'error')
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
        content = request.form.get('content', None)
        create = request.form.get('create', '0')  # default zero; TODO: rewrite this
        if not page_name or page_name == '.gitignore' or '.' in page_name or '/' in page_name:
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
            except Exception:
                abort(500)
    return render_template('editor.html', context={})


@app.route('/write/<page_name>', methods=['POST', 'GET'])
@access_check
def edit(page_name):
    """ Edit existed page with <page_name> title """
    content = ''
    page_name = escape(page_name)
    if not page_name or page_name == '.gitignore' or '.' in page_name or '/' in page_name:
        abort(404)
    page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
    try:
        with open(page_file, 'r') as f:
            content = f.read()
    except OSError:
        abort(404)
    except Exception:
        abort(500)
    return render_template('editor.html', context={'title': page_name, 'content': content})


@app.route('/delete/<page_name>', methods=['GET'])
@access_check
def delete_page(page_name):
    """ Delete page with <page_name> filename. """
    if not page_name or page_name == '.gitignore' or '.' in page_name or '/' in page_name:
        abort(404)
    if '$' in page_name:
        page_file = safe_join(app.config['FEEDBACK_FOLDER'], page_name)
    elif '@' in page_name:
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
    except Exception:
        abort(500)
    return redirect(url_for('main'))


@app.route('/restore/<dump_name>', methods=['GET'])
@access_check
def restore(dump_name):
    """ Restore page from dump storage """
    if not dump_name or dump_name == '.gitignore' or '.' in dump_name or '/' in dump_name:
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
    delete = request.args.get('delete', None)
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
    if delete is not None:
        file = safe_join(app.config['UPLOAD_FOLDER'], delete)
        try:
            os.remove(file)
            flash('Success!', 'info')
        except FileNotFoundError:
            flash('File not found!', 'error')
        except Exception:
            abort(500)
    files = show_files()
    return render_template('upload.html', context={"files": files})


@app.route('/feedback/', methods=['GET'])
@access_check
def feedback():
    """ View all feedback in folder"""
    feedback_all = show_feedback_all()
    return render_template('feedback_all.html', context={'feedback': feedback_all})


@app.route('/feedback/view/<page_name>', methods=['GET'])
@access_check
def feedback_view(page_name):
    """ Render page with content from feedback file """
    if not page_name or page_name == '.gitignore':
        abort(404)
    feedback_info = page_name.split('$')
    feedback_info[3] = datetime.datetime.fromtimestamp(int(feedback_info[3])).strftime('%d-%m-%Y %H:%M')
    feedback_file = safe_join(app.config['FEEDBACK_FOLDER'], page_name)
    with open(feedback_file) as f:
        content = f.read()
    return render_template('feedback_view.html', context={'feedback': feedback_info, 'content': content})


@app.route('/feedback/<page_name>', methods=['GET', 'POST'])
def feedback_on_page(page_name):
    """ Write user feedback to file. """
    if not page_name or page_name == '.gitignore' or '.' in page_name or '/' in page_name:
        abort(404)
    feedback_all = []
    if 'username' in session:
        feedback_all = show_feedback(page_name)
    if request.method == 'POST':
        name = escape(request.form.get('name', ''))
        email = escape(request.form.get('email', ''))
        content = request.form.get('content', '')
        timestamp = str(int(time.time()))
        file = safe_join(app.config['FEEDBACK_FOLDER'], '$'.join([page_name, name, email, timestamp]))
        if not name or not email or not content:
            flash('Please, fill all fields!', 'error')
            return redirect(url_for('feedback_on_page', page_name=page_name))
        with open(file, 'w') as f:
            f.write(content)
        flash('Thank you for feedback.', 'info')
        return redirect(url_for('page', page_name=page_name))
    return render_template('feedback.html', context={"title": page_name, "feedback": feedback_all})


@app.route('/admin/', methods=['GET', 'POST'])
@access_check
def admin():
    """ Admin panel handler. """
    if session['username'] != app.config['ADMIN_LOGIN']:
        abort(403)
    if request.method == 'POST':
        form = request.form.get('form')
        if form == 'create_user':
            username = escape(request.form.get('username', ''))
            password = request.form.get('password', '')
            if not username or not password:
                flash('Fill all fields!', 'error')
                return redirect(url_for('admin'))
            try:
                Admin.create_user(username, password)
                flash('Success!', 'info')
            except FileExistsError:
                flash('User exist!', 'error')
            except OSError:
                flash('Can not create new user!', 'error')
            except Exception:
                abort(500)
            finally:
                return redirect(url_for('admin'))
        elif form == 'delete_user':
            username = escape(request.form.get('username', ''))
            if not username:
                flash('Fill all fields!', 'error')
                return redirect(url_for('admin'))
            try:
                Admin.delete_user(username)
                flash('Success!', 'info')
            except FileNotFoundError:
                flash('User not found!', 'error')
            except Exception:
                abort(500)
            finally:
                return redirect(url_for('admin'))
    return render_template('admin.html', context={"users": Admin.show_users()})


@app.route('/search/', methods=['GET'])
def search():
    query = request.args.get('q', None)
    result = []
    if query is not None:
        pages = show_pages()
        for page_name in pages:
            page_file = safe_join(app.config['PAGES_FOLDER'], page_name)
            with open(page_file) as f:
                for line in f:
                    if query in line:
                        result.append({'name': page_name, 'line': line})
    return render_template('search.html', context={"result": result})


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
