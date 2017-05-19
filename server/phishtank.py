import requests
from json import JSONDecoder
from bz2 import BZ2Decompressor
from io import StringIO

class PhishTank(object):
    FILE_URL="http://data.phishtank.com/data/online-valid.json.bz2"

    @staticmethod
    def run(cache):
        res = requests.get(PhishTank.FILE_URL)
        if res.status_code != requests.codes.ok:
            raise ValueError("error fetching file: {} - {}".format(res.status_code, res.text))
        # let any error bubble up
        archive = StringIO()
        decompressor = BZ2Decompressor()
        data = decompressor.decompress(res.content)
        archive.write(data.decode("us-ascii"))
        dec = JSONDecoder()
        json_data = dec.decode(archive.getvalue())
        url_count = len(json_data)
        for item in json_data:
            url = item.get("url")
            if url:
                cache.setex(url, 86400, "suspicious")
        return url_count

if __name__=="__main__":
    data = PhishTank.run(None)
    from pprint import pprint
    pprint(data)
