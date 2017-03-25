from functools import wraps

from flask import request, redirect, url_for, session

from config import get_config
from util.postgres import get_connection

config = get_config()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user') is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def check_credentials(username, md5password):
    conn = get_connection()

    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=%s AND password=%s', [username, md5password])
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user is not None


def change_password(new_password):

    try:
        user = session.get('user')

        conn = get_connection()

        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password=%s WHERE username=%s', [new_password, user])
        conn.commit()
        cursor.close()
        conn.close()
        return True

    except Exception as e:
        print e
        return False

