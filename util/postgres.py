import psycopg2
import hashlib
from config import get_config

config = get_config()
default_user = 'admin'
default_password = 'admin'


def init_db():
    conn = get_connection()

    if conn is None:
        raise (Exception('Cannot connect to db, initalizazion failed'))

    c = conn.cursor()

    try:
        # creating the table that will contain logs
        c.execute('CREATE TABLE IF NOT EXISTS events ( \
                        id SERIAL PRIMARY KEY, \
                        moment BIGINT NOT NULL,\
                        body TEXT NOT NULL,\
                        level VARCHAR(16) NOT NULL);')
        conn.commit()

        # creatubg the table that will contain users
        c.execute('CREATE TABLE IF NOT EXISTS users ( \
                    id SERIAL PRIMARY KEY, \
                    username VARCHAR(255) NOT NULL, \
                    password VARCHAR(32) NOT NULL);')
        conn.commit()

        # creating an "admin" user if doesn't already exists
        c.execute('SELECT * FROM users WHERE id=1;')

        if c.fetchone() is None:
            password_md5 = hashlib.md5(default_password).hexdigest()
            c.execute('INSERT INTO users (username, password) VALUES (%s, %s);', [default_user, password_md5])
            conn.commit()

        c.close()
        conn.close()

    except Exception as e:
        print(e)
        raise e


def get_connection():
    try:
        return psycopg2.connect(
            host=config['postgres_host'],
            user=config['postgres_user'],
            password=config['postgres_password'],
            database=config['postgres_db'],
            port=config['postgres_port']
        )
    except Exception as e:
        print(e)
        return None
