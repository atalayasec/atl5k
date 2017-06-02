import hashlib
import magic
import random
import string
import socket
import datetime
import redis
import requests
import tld

from config import get_config

config = get_config()
files_container = config['quarantine_folder']
live_config = redis.StrictRedis(
    host=config['redis_host'], port=config['redis_port'], db=1)

INSPECTOR_CACHED = "http://127.0.0.1:8080"


class Result(object):
    '''Fake result object to maintain compatibility with the
    unnominable API'''
    status = None
    msg = None


def get_api_key():
    return live_config.get('api_key')


def checkMD5(sample_md5):
    r = requests.get(INSPECTOR_CACHED + "/vt/hash/{}".format(sample_md5))
    data = r.json()
    result = data.get("result")
    if result == "unknown":
        return 'unknown'
    if isinstance(result, dict):
        score = result.get("score")
        if score < 50.0:
            return 'clean'
        else:
            return 'malicious'


def syslog(message,
           level=6,
           facility=1,
           host='CONFIGURABLE LOG SERVER',
           port='CONFIGURABLE PORT'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    now = datetime.datetime.now()
    data = '48' + now.strftime('%b %d %H:%M:%S') + ' %s' % (
        "host=p-5000," + message)
    sock.sendto(data, (host, port))
    sock.close()


def getFQDN(url):
    return url.split('/')[2]


def getIP(fqdn):
    return socket.gethostbyname_ex(fqdn)[2][0]


def checkIP(ip):
    return safebrowsing_check_url(ip)


def checkDomain(domain):
    return checkIP(domain)


def md5(payload):
    hash = hashlib.md5()
    hash.update(payload)
    return hash.hexdigest()


def checkMagic(payload):
    m = magic.Magic(uncompress=True)
    header = m.from_buffer(payload)
    return header.startswith('PE32')


def randomword():
    return ''.join(random.choice(string.lowercase) for i in range(30))


def payloadToFile(path, payload):
    f = open(path, 'wb')
    f.write(payload)
    f.close()


def writePayload(payload, file_extension):
    filename = randomword()
    if file_extension != '':
        filename += '.' + file_extension
    payloadToFile(files_container + filename, payload)
    return filename


def upload_file(file_name, body):
    r = Result()
    r.status = "FAKE_SUCCESS"
    r.msg = "do not trust this result"
    return r


def safebrowsing_check_url(url):
    apikey = live_config.get("safebrowsing_api_key")
    if not apikey:
        return "unknown"
    request_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}".format(
        apikey)
    request_data = {
        "client": {
            "clientId": "thesecuritystack",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": {
                "url": url
            }
        }
    }
    result = requests.post(
        request_url,
        headers={"Content-Type": "application/json"},
        json=request_data)
    ret = "unknown"
    try:
        json_data = result.json()
        if len(json_data.get("matches", [])) > 0:
            ret = "suspicious"
        else:
            ret = "clean"
    except ValueError:
        pass
    print("safebrowsing result: {}".format(ret))
    return ret


def domain_cache(domain, logger, cache, memory_cache):
    whitelist = redis.StrictRedis(
        host=config['redis_host'], port=config['redis_port'], db=3)
    # checking for domain in whitelist
    is_whitelisted = whitelist.get(domain)
    if is_whitelisted:
        logger.info('Domain {0} is whitelisted, pass'.format(domain))
    else:
        # try subdomain
        top_domain = tld.get_tld(domain, fix_protocol=True, fail_silently=True)
        if whitelist.get(top_domain):
            logger.info('{} is subdomain of {} which is whitelisted, pass'.
                        format(domain, top_domain))
            return
        # handle in memory cache
        if domain in memory_cache:
            quality = memory_cache.get(domain)
        # in memory_cache not found, check redis cache
        else:
            quality = cache.get(domain)
        if quality:
            logger.info(
                'Domain {0} quality information taken from local cache'.format(
                    domain))
    return quality
