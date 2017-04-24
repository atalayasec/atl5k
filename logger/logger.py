import time
import logging
from logging.handlers import SysLogHandler

from config import get_config
from util.postgres import get_connection

config = get_config()


def now():
    return int(round(time.time() * 1000))


class DVLogger:
    def __init__(self):
        self.conn = get_connection()
        self.remote_syslog = None

    def enable_syslog(self, host, port):
        if not host or not port:
            return
        logger = logging.getLogger("{}:{}".format(host, port))
        h = SysLogHandler(address=(str(host), int(port)))
        h.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        if len(logger.handlers) < 1:
            logger.addHandler(h)
        self.remote_syslog = logger

    def disable_syslog(self):
        self.remote_syslog = None

    def info(self, body):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO events(moment, body, level) VALUES (%s, %s, %s)",
                       [now(), body, 'INFO'])
        self.conn.commit()
        cursor.close()
        if self.remote_syslog:
            self.remote_syslog.info("{}".format(body))

    def close(self):
        self.conn.close()



