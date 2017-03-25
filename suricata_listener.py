import pyinotify
import os
from multiprocessing import Process
from config import get_config
import redis
from util.suricata import *
from analysis_handlers import suricata_domain_handler, suricata_file_handler, suricata_ip_handler
from logger.logger import DVLogger
import pylru # https://pypi.python.org/pypi/pylru

config = get_config()
live_config = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=1)
cache = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=4)

FILES_DIR = os.environ.get("SURICATA_WATCHER_FILES_DIR", "/var/log/suricata/files")
# FILES_DIR = os.environ.get("SURICATA_WATCHER_FILES_DIR", "/home/duma/Documenti")
LOG_DNS = "/var/log/suricata/dns.log"
# LOG_DNS = "/home/duma/test.log"
LOG_HTTP = "/var/log/suricata/http.log"
PIDFILE="/var/run/surifiles.pid"

RE_DNS = r"^.+\[\*\*\] Query [ a-zA-Z0-9]+ \[\*\*\] (?P<domain>[a-zA-Z0-9\-\.\_]+) \[\*\*\] [ a-zA-Z0-9]+ \[\*\*\] (?P<SRC_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<SRC_PORT>\d+) -> (?P<DST_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<DST_PORT>\d+)$"
RE_HTTP = r"^[\w\-\:\.\/]+ (?P<domain>[a-zA-Z0-9\-\.\_]+) .+ (?P<SRC_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<SRC_PORT>\d+) -> (?P<DST_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<DST_PORT>\d+)$"

MEMORY_CACHE_SIZE=100000
memory_cache = pylru.lrucache(MEMORY_CACHE_SIZE)

logger = DVLogger()
syslogEnabled = live_config.get("syslogEnabled")
if syslogEnabled:
    host = live_config.get("syslogHost")
    port = live_config.get("syslogPort")
    logger.enable_syslog(host, port)
else:
    logger.disable_syslog()


# Files handling
class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        if r.match(event.pathname):
            upload_file_if_unknown = live_config.get('upload_file_if_unknown') == 'True'
            p = Process(target=new_file_handler, args=(event, suricata_file_handler.handle,cache,memory_cache, upload_file_if_unknown, logger))
            p.start()


wm = pyinotify.WatchManager()
mask = pyinotify.IN_CREATE
r = re.compile(r".*\.[0-9]+$")

handler = EventHandler()
notifier = pyinotify.Notifier(wm, handler)
wdd = wm.add_watch(FILES_DIR, mask, rec=False)

# Domains handling
domain_process = Process(target=parse_dns_log, args=(LOG_DNS,
                                                     RE_DNS,
                                                     suricata_domain_handler.handle,
                                                     cache,memory_cache,
                                                     logger))
domain_process.daemon = True


http_process = Process(target=parse_http_log, args=(LOG_HTTP,
                                                    RE_HTTP,
                                                    suricata_domain_handler.handle,
                                                    cache,memory_cache,
                                                    logger))
http_process.daemon = True


# starting all loops
#http_process.start()
domain_process.start()
notifier.loop()
