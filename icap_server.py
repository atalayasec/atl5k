import SocketServer
import argparse
import os
import signal
import tempfile

import redis
import pylru # https://pypi.python.org/pypi/pylru

from config import get_config
from analysis_handlers.icap_domain import check_domain_quality
from analysis_handlers.icap_file import check_file_quality
from analysis_handlers.icap_ip import check_ip_quality
from logger.logger import DVLogger
from pyicap import ICAPServer, BaseICAPRequestHandler
from util.flask import get_host

parser = argparse.ArgumentParser(description='icap_server')
parser.add_argument("--port", "-p", type=int, help="listen port")
args = parser.parse_args()

MEMORY_CACHE_SIZE=100000

config = get_config()
port = int(args.port)

# redis cache and whitelist
interprocess_comunication = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=1)
cache = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=4)

memory_cache = pylru.lrucache(MEMORY_CACHE_SIZE)

def pheFei5Kpmh32Ja6(sig, frame):
    pid = os.getpid()
    fd, path = tempfile.mkstemp(text=True, prefix="icap_cache_{}_".format(pid))
    with open(path, "w") as f:
        for k,v in memory_cache.items():
            f.write("{}:  {}\n".format(k, v))
    os.close(fd)

signal.signal(signal.SIGUSR2, pheFei5Kpmh32Ja6)


class ThreadingSimpleServer(SocketServer.ThreadingMixIn, ICAPServer):
    pass


class ICAPHandler(BaseICAPRequestHandler):
    def response_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'RESPMOD')
        self.set_icap_header('Preview', '0')
        self.set_icap_header('Max-Connections', '1000')
        self.send_headers(False)

    def response_RESPMOD(self):
        pass_mode = interprocess_comunication.get('proxy_mode') == 'monitor'
        my_logger = DVLogger()
        syslogEnabled = interprocess_comunication.get("syslogEnabled")
        if syslogEnabled:
            host = interprocess_comunication.get("syslogHost")
            port = interprocess_comunication.get("syslogPort")
            my_logger.enable_syslog(host, port)
        else:
            my_logger.disable_syslog()

        url = self.enc_req[1]
        if url.startswith(get_host()):
            self.no_adaptation_required()
            return

        # checking IP quality
        block = check_ip_quality(
            icap_response=self,
            url=url,
            memory_cache=memory_cache,
            logger=my_logger,
            cache=cache,
            pass_mode=pass_mode
        )

        if block:
            my_logger.info("ip {} blocked".format(url))
            my_logger.close()
            return

        #  check domain quality
        block = check_domain_quality(
            icap_response=self,
            url=url,
            memory_cache=memory_cache,
            logger=my_logger,
            cache=cache,
            pass_mode=pass_mode
        )

        if block:
            my_logger.info("domain {} blocked".format(url))
            my_logger.close()
            return

        # checking file quality if is a file
        if self.has_body:
            block = check_file_quality(
                icap_response=self,
                logger=my_logger,
                cache=cache,
                pass_mode=pass_mode
            )
            my_logger.info("file blocked")
            my_logger.close()
            return

        my_logger.close()
        self.no_adaptation_required()


# ---------------------------------------------------------------------------------------------------------------------#
# init sequence


# writing pid into a file
# pid = str(os.getpid())
# f = open('/tmp/atl5k.pid', 'w+')
# f.write(pid)
# f.close()


# def load_whitelist():
#     # loading initial data from whitelist csv
#     try:
#         white_domain = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=3)
#         trusted_domains = open(config['whitelist_csv'], 'r')
#         r = csv.reader(trusted_domains, delimiter=',')
#         print('Loading whitelist into redis\n')
#         for row in r:
#             white_domain.set(row[1], True)
#
#         trusted_domains.close()
#     except IOError as e:
#         # whitelist csv not found, just pass
#         print('No whitelist CSV found\n')

print('Starting ICAP daemon on port {0}\n'.format(port))
server = ThreadingSimpleServer(('', port), ICAPHandler)

# thread = threading.Thread(target=load_whitelist)

try:
    # thread.run()
    while True:
        server.handle_request()
except KeyboardInterrupt:
    exit()
