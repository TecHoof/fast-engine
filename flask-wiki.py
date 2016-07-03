# FIXME: DOCUMENTATION
from json import load, dumps
from passlib.hash import sha256_crypt
from flask import Flask, session, flash, request, render_template, redirect, url_for

app = Flask(__name__)
app.config.update(
    DEBUG=True,
    SECRET_KEY='Every pony is the best pony!',
    SESSION_COOKIE_NAME='library',
    SITE_TITLE='Flask Wiki',
    USERS_PATH=app.root_path + '/system/users/'
)


@app.route('/')
def main():
    return render_template('main.html', content='<h1>This is main page!</h1>')


@app.route('/login/', methods=['POST', 'GET'])
def login():  # TODO: error handling
    # FIXME: DOCUMENTATION
    if 'username' in session:
        flash('You are already logged in!', 'info')  #
        return redirect(url_for('main'))             # FIXME: decorate this!
    if request.method == 'POST':
        # TODO: add input check
        username = request.form['username']
        password = request.form['password']
        app.logger.debug(request.form['username'])
        try:
            user_file = open(app.config['USERS_PATH'] + username, 'r')  # user_file on json format
            user_conf = load(user_file)
            user_file.close()
            if not sha256_crypt.verify(password, user_conf['password']):
                flash('Wrong password!', 'error')
                return redirect(url_for('login'))
            else:
                flash('You successfully logged in!', 'info')
                session['username'] = request.form['username']
        except FileNotFoundError:
            flash('User not exist!', 'error')
            return redirect(url_for('login'))
        except Exception:
            flash('Internal server error!', 'error')
        return redirect(url_for('main'))

    return render_template('login.html')


@app.route('/reg/', methods=['POST', 'GET'])
def reg():  # TODO: error handling
    # FIXME: DOCUMENTATION
    if 'username' in session:                        #
        flash('You are already logged in!', 'info')  # FIXME: decorate this!
        return redirect(url_for('main'))             #
    if request.method == 'POST':
        # TODO: add input check
        username = request.form['username']
        password = request.form['password']
        password = sha256_crypt.encrypt(password)
        try:
            user_file = open(app.config['USERS_PATH'] + username, 'x')
            user_file.write(dumps({'password': password}))
            user_file.close()
            flash('Success!', 'info')
            return redirect(url_for('main'))
        except FileExistsError:
            flash('User exist!', 'error')
        except OSError:
            flash('Registration failed!', 'error')
    return render_template('reg.html')


@app.route('/logout/')
def logout():
    # FIXME: DOCUMENTATION
    if 'username' in session:
        session.pop('username', None)
        flash('You successfully logged out!', 'info')
        return redirect('/')
    flash('You are not logged in!', 'error')
    return redirect('/')


if __name__ == '__main__':
    app.run()
