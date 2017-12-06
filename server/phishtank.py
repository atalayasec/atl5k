import requests
from json import JSONDecoder
from bz2 import BZ2Decompressor
from io import StringIO
import time
from named_logger import NamedLogger
import multiprocessing


class PhishTank(multiprocessing.Process, NamedLogger):
    __logname__ = "phishtank"
    FILE_URL = "https://data.phishtank.com/data/{}/online-valid.json.bz2"

    def __init__(self, cache, config):
        multiprocessing.Process.__init__(self)
        self.setup_logger()
        self.cache = cache
        self.config = config

    def run(self):
        while True:
            delay = self.config.get("phishtank_update_delay")
            try:
                delay = int(delay)
            except (ValueError, TypeError):
                delay = 0
            if delay < 1:
                self.logger.info("update not set or <1, not running")
                time.sleep(60)
                continue
            if delay < 3600:
                self.logging.info("specified delay of {} too short, forcing to 1 hour".format(delay))
                delay = 3600

            apikey = self.config.get("phishtank_api_key")
            if not apikey:
                self.logger.info("apikey not configured, not running")
                continue

            self.logger.info("running phishtank update operation")
            res = requests.get(PhishTank.FILE_URL.format(apikey))
            if res.status_code != requests.codes.ok:
                self.logging.info("error fetching file: {} - {}".format(res.status_code, res.text))
                continue
            # let any error bubble up
            archive = StringIO()
            decompressor = BZ2Decompressor()
            data = decompressor.decompress(res.content)
            archive.write(data.decode("us-ascii"))
            dec = JSONDecoder()
            json_data = dec.decode(archive.getvalue())
            for item in json_data:
                url = item.get("url")
                if url:
                    self.cache.setex(url, delay, "suspicious")
            self.logger.info("phishtank update operation completed")
            time.sleep(delay)
