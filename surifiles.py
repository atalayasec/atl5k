# #!/usr/bin/env python
#
# import re
# import time
# import signal
# import os
# import sys
#
# from multiprocessing import Process, Queue
# import tldextract
#
# LOG_DNS = "/var/log/suricata/dns.log"
# LOG_HTTP = "/var/log/suricata/http.log"
# PIDFILE="/var/run/surifiles.pid"
#
# RE_DNS = r"^.+\[\*\*\] Query [ a-zA-Z0-9]+ \[\*\*\] (?P<domain>[a-zA-Z0-9\-\.\_]+) \[\*\*\] [ a-zA-Z0-9]+ \[\*\*\] (?P<SRC_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<SRC_PORT>\d+) -> (?P<DST_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<DST_PORT>\d+)$"
# RE_HTTP = r"^[\w\-\:\.\/]+ (?P<domain>[a-zA-Z0-9\-\.\_]+) .+ (?P<SRC_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<SRC_PORT>\d+) -> (?P<DST_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<DST_PORT>\d+)$"
#
# LOG_QUEUE = Queue()
#
#
# global p0
#
#
#
# global p1
#
# global p2
#
#
#
# def handler_fin(signum, frame):
#   p0.terminate()
#   p1.terminate()
#   p2.terminate()
#   sys.exit(0)
#
# signal.signal(signal.SIGINT, handler_fin)
# signal.signal(signal.SIGTERM, handler_fin)
#
# with open(PIDFILE, "w+") as f:
#   f.write(str(os.getpid()))
#
# while True:
#   time.sleep(5)
