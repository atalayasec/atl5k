import re
import time
import tldextract
from logger.logger import DVLogger
import subprocess

local_filter = set([])


def retrying_open(filename, mode):
    while True:
        try:
            fd = open(filename, mode)
            return fd
        except:
            time.sleep(5)


def parse_http_log(filename, regex, domain_handler, ip_handler, cache, memory_cache, logger):
    r = re.compile(regex)
    r2 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    logfile = retrying_open(filename, "r")

    loglines = follow(logfile)
    for line in loglines:
        m = r.match(line)
        if m:
            host = m.group("domain")
            if  not r2.match(host):
                if not host in local_filter:
                    domain_handler(host, logger, cache)
            else:
                ip_handler(host, logger, cache)


def parse_dns_log(filename, regex, domain_handler, cache, memory_cache, logger):
    r = re.compile(regex)
    logfile = retrying_open(filename, "r")

    loglines = follow(logfile)
    for line in loglines:
        m = r.match(line)
        if m:
            domain = m.group("domain")
            if not domain in local_filter:
                domain_handler(domain, logger, cache, memory_cache)


def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


def consume_log(queue):
    while True:
        msg = queue.get()
        print msg


def new_file_handler(event, handler, cache, memory_cache, upload_mode, logger):
    proc = subprocess.check_output(['md5sum', event.pathname])
    md5 = proc.split(' ')[0]

    handler(md5, event, logger, cache, memory_cache, upload_mode)
