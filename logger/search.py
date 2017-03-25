from config import get_config
from util.postgres import get_connection

config = get_config()


def list_to_dict(l):
    return {
        'id': l[0],
        'moment': l[1],
        'body': l[2],
        'level': l[3]
    }


def rows_to_dict(rows):
    dicts = []
    for row in rows:
        dicts.append(list_to_dict(row))

    return dicts


def logs_generic_search(string, start, stop):
    db = get_connection()

    second = False
    query = "SELECT * FROM events "

    data = []

    if string:
        second = True
        query += 'WHERE body ~* %s '
        data.append('.*' + string + '.*')

    if start and stop:
        data.append(int(start))
        data.append(int(stop))
        if second:
            query += 'AND moment > %s AND moment < %s'
        else:
            query += 'WHERE moment > %s AND moment < %s'

    query += 'ORDER by moment desc;'

    cursor = db.cursor()
    cursor.execute(query, data)
    res = cursor.fetchall()
    cursor.close()

    dicts = []
    for row in res:
        dicts.append(list_to_dict(row))

    db.close()
    return dicts


def get_blocked_ips_24():
    db = get_connection()
    ms_24h = 24 * 3600 * 1000
    c = db.cursor()
    c.execute('SELECT COUNT(*) FROM events WHERE body ~* \'^IP.*block$\' AND moment > %s;', [ms_24h])
    res = c.fetchone()
    c.close()
    db.close()
    return int(res[0])


def get_blocked_domains_24():
    db = get_connection()
    ms_24h = 24 * 3600 * 1000
    c = db.cursor()
    c.execute('SELECT COUNT(*) FROM events WHERE body ~* \'^Domain.*block$\' AND moment > %s;', [ms_24h])
    res = c.fetchone()
    c.close()
    db.close()
    return int(res[0])


def get_blocked_files_24():
    db = get_connection()
    ms_24h = 24 * 3600 * 1000
    c = db.cursor()
    c.execute('SELECT COUNT(*) FROM events WHERE body ~* \'^File.*block$\' AND moment > %s;', [ms_24h])
    res = c.fetchone()
    c.close()
    db.close()
    return int(res[0])
