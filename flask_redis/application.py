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
import schema
import messages
from decorators import admin_required, login_required

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
    user_key = schema.USERS.format(username)
    user = g.db.get(user_key)
    if not user:
        flash(messages.INVALID_USERNAME_PASSWORD, 'error')
    else:
        user_data = json.loads(user)
        if utils.encrypt_password(password, app.config['SECRET_KEY']) == user_data['password']:
            auth_token = str(uuid.uuid4())
            user_data['auth_token'] = auth_token
            g.db.set(user_key, json.dumps(user_data))
            session['user'] = username
            session['role'] = user_data['role']
            session['auth_token'] = auth_token
        else:
            flash(messages.INVALID_USERNAME_PASSWORD, 'error')
    return redirect(url_for('index'))

@app.route("/logout/", methods=['GET'])
def logout():
    if 'auth_token' in session:
        session.pop('auth_token')
    if 'role' in session:
        session.pop('role')
    if 'user' in session:
        user_key = schema.USERS.format(session['user'])
        user = g.db.get(user_key)
        user_data = json.loads(user)
        g.db.set(user_key, json.dumps(user_data))
        session.pop('user')
        flash(messages.LOGGED_OUT)
    return redirect(url_for('index'))

@app.route("/users/")
@admin_required
def users():
    users = []
    roles = []
    user_keys = g.db.keys(schema.USERS.format('*'))
    # sort
    user_keys.sort()
    for u in user_keys:
        user_data = json.loads(g.db.get(u))
        users.append(user_data)
    role_keys = g.db.keys(schema.ROLES.format('*'))
    # sort
    role_keys.sort()
    for r in role_keys:
        role_data = json.loads(g.db.get(r))
        roles.append(role_data)
    # sort
    ctx = {
        'users': users,
        'roles': roles,
    }
    return render_template('users.html', **ctx)

@app.route("/users/adduser/", methods=['POST'])
@admin_required
def add_user():
    form = request.form
    try:
        utils.create_user(username=form['username'], password=form['password'], \
            role=form['role'], active=True)
        flash(messages.USER_CREATED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.NEW_USER_ERROR, e), 'error')
    return redirect(url_for('users'))

@app.route("/users/toggleuser/<username>/")
@admin_required
def toggle_user(username):
    try:
        utils.toggle_user(username)
    except Exception, e:
        flash('{0} {1}'.format(messages.ERROR_DISABLING_USER, e), 'error')
    return redirect(url_for('users'))

@app.route("/users/deleteuser/<username>/")
@admin_required
def delete_user(username):
    try:
        utils.delete_user(username)
        flash(messages.USER_DELETED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.ERROR_DELETING_USER, e), 'error')
    return redirect(url_for('users'))

@app.route("/users/addrole/", methods=['POST'])
@admin_required
def add_role():
    form = request.form
    try:
        utils.create_role(form['rolename'])
        flash(messages.ROLE_CREATED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.NEW_ROLE_ERROR, e), 'error')
    return redirect(url_for('users'))

@app.route("/users/deleterole/<rolename>/")
@admin_required
def delete_role(rolename):
    try:
        utils.delete_role(rolename)
        flash(messages.ROLE_DELETED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.ERROR_DELETING_ROLE, e), 'error')
    return redirect(url_for('users'))



# ----- management command -----
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
        # create role if needed
        if not redis.get(schema.ROLES.format(role)):
            utils.create_role(role)
        utils.create_user(username=username, password=password, role=role, active=True)
        print('User created/updated successfully...')
    except KeyboardInterrupt:
        pass

def toggle_user(active):
    try:
        redis = get_redis_connection()
        username = raw_input('Enter username: ').strip()
        try:
            utils.toggle_user(username, active)
        except Exception, e:
            print(e)
            sys.exit(1)
    except KeyboardInterrupt:
        pass

if __name__=="__main__":
    op = OptionParser()
    op.add_option('--create-user', dest='create_user', action='store_true', default=False, help='Create/update user')
    op.add_option('--enable-user', dest='enable_user', action='store_true', default=False, help='Enable user')
    op.add_option('--disable-user', dest='disable_user', action='store_true', default=False, help='Disable user')
    opts, args = op.parse_args()

    if opts.create_user:
        create_user()
        sys.exit(0)
    if opts.enable_user:
        toggle_user(True)
        sys.exit(0)
    if opts.disable_user:
        toggle_user(False)
        sys.exit(0)
    # run app
    app.run()


