from flask import Flask
from flask import jsonify
from flask import json
from flask import request, Response
from flask import session
from flask import g
from flask import render_template
from flask import redirect, url_for
from flask import flash
import os
import uuid
import logging
import sys
import settings
from optparse import OptionParser
from getpass import getpass
import redis
import utils
import queue

app = Flask(__name__)
app.debug = settings.DEBUG
app.logger.setLevel(logging.ERROR)
app.config.from_object('settings')

@app.before_request
def before_request():
    g.db = get_redis_connection()

@app.teardown_request
def teardown_request(exception):
    pass

def get_redis_connection():
    return redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, \
        db=settings.REDIS_DB, password=settings.REDIS_PASSWORD)

@app.route("/")
def index():
    if 'auth_token' in session:
        return render_template("index.html")
    else:
        return redirect(url_for('about'))

@app.route("/about/")
def about():
    return render_template("about.html")

@app.route("/login/", methods=['GET', 'POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user_key = 'users:{0}'.format(username)
    user = g.db.get(user_key)
    if not user:
        flash('Invalid username/password', 'error')
    else:
        user_data = json.loads(user)
        if utils.encrypt_password(password, app.config['SECRET_KEY']) == user_data['password']:
            auth_token = str(uuid.uuid4())
            user_data['auth_token'] = auth_token
            g.db.set(user_key, json.dumps(user_data))
            session['user'] = username
            session['auth_token'] = auth_token
        else:
            flash('Invalid username/password', 'error')
    return redirect(url_for('index'))

@app.route("/logout/", methods=['GET'])
def logout():
    if 'auth_token' in session:
        session.pop('auth_token')
    if 'user' in session:
        user_key = 'users:{0}'.format(session['username'])
        user = g.db.get(user_key)
        user_data = json.loads(user)
        user_data.pop('auth_token')
        g.db.set(user_key, json.dumps(user_data))
        session.pop('user')
        flash('You have been logged out...')
    return redirect(url_for('index'))

# ----- helper commands -----
def create_user():
    try:
        redis = get_redis_connection()
        username = raw_input('Username: ').strip()
        while True:
            password = getpass('Password: ')
            password_confirm = getpass(' (confirm): ')
            if password_confirm == password:
                break
            else:
                print('Passwords do not match... Try again...')
        role = raw_input('Role: ').strip()
        data = {
            'password': utils.encrypt_password(password, app.config['SECRET_KEY']),
            'role': role,
        }
        redis.set('users:{0}'.format(username), json.dumps(data))
        print('User created successfully...')
    except KeyboardInterrupt:
        pass

if __name__=="__main__":
    op = OptionParser()
    op.add_option('--create-user', dest='create_user', action='store_true', default=False, help='Create/update user')
    opts, args = op.parse_args()

    if opts.create_user:
        create_user()
        sys.exit(0)
    # run app
    app.run()


