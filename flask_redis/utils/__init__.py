import hashlib
import schema
import application
import settings
try:
    import simplejson as json
except ImportError:
    import json

def create_user(username=None, password=None, role=None, active=True):
    if not username or not password or not role:
        raise NameError('You must specify a username, password, and role')
    redis = application.get_redis_connection()
    data = {
        'username': username,
        'password': encrypt_password(password, settings.SECRET_KEY),
        'role': role,
        'active': active,
    }
    redis.set(schema.USERS.format(username), json.dumps(data))
    return True

def create_role(rolename=None):
    if not rolename:
        raise NameError('You must specify a rolename')
    redis = application.get_redis_connection()
    data = {'name': rolename}
    redis.set(schema.ROLES.format(rolename), json.dumps(data))
    return True

def delete_user(username=None):
    if not username:
        raise NameError('You must specify a username')
    redis = application.get_redis_connection()
    redis.delete(schema.USERS.format(username))
    return True

def delete_role(rolename=None):
    if not rolename:
        raise NameError('You must specify a rolename')
    redis = application.get_redis_connection()
    redis.delete(schema.ROLES.format(rolename))
    return True

def toggle_user(username=None, active=None):
    if not username:
        raise NameError('You must specify a username')
    redis = application.get_redis_connection()
    user_data = redis.get(schema.USERS.format(username))
    if user_data:
        user_data = json.loads(user_data)
        if active != None:
            user_data['active'] = active
        else:
            current_status = user_data['active']
            if current_status:
                user_data['active'] = False
            else:
                user_data['active'] = True
        redis.set(schema.USERS.format(username), json.dumps(user_data))
        if active:
            status = 'active'
        else:
            status = 'disabled'
        return True
    else:
        raise RuntimeError('User not found')


def encrypt_password(password=None, salt=None):
    h = hashlib.sha256(salt)
    h.update(password+salt)
    return h.hexdigest()
