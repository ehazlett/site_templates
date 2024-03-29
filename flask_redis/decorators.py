#!/usr/bin/env python
from functools import wraps
from flask import g, session, redirect, url_for
from flask import flash
from flask import json
import schema
import messages

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session or 'auth_token' not in session:
            flash(messages.ACCESS_DENIED, 'error')
            return redirect(url_for('index'))
        user_data = json.loads(g.db.get(schema.USERS.format(session['user'])))
        if 'role' not in user_data or user_data['role'].lower() != 'admin':
            flash(messages.ACCESS_DENIED, 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'auth_token' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

