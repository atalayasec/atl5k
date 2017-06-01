import redis

import deepint
from config import get_config
from util.flask import get_host

config = get_config()
whitelist = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=2)


def check_ip_quality(url, memory_cache, logger, cache, pass_mode, icap_response):

    fqdn = deepint.getFQDN(url)
    ip = deepint.getIP(fqdn)

    # checking for ip in whitelist
    is_whitelisted = whitelist.get(ip)
    if not is_whitelisted:
        logger.info("NOT whitelisted {}".format(ip))
        # handle memory cache
        if ip in memory_cache:
            quality = memory_cache.get(ip)
        # in memory cache not found, check redis
        else:
            logger.info("MISS from in-memory cache {}".format(ip))
            # handling local cache
            quality = cache.get(ip)
        if not quality:
            logger.info("MISS from cache {}".format(ip))
            quality = deepint.checkIP(ip)
            cache.setex(ip, config['local_cache_expiration_seconds'], quality)
            memory_cache[ip] = quality

        if quality == 'suspicious':
            if pass_mode:
                logger.info('IP {0} is malicious, pass'.format(ip))
            else:
                logger.info('IP {0} is malicious, block'.format(ip))
                icap_response.set_icap_response(200)
                icap_response.set_enc_status('HTTP/1.1 307 Temporary Redirect')
                icap_response.set_enc_header('location', get_host() + '/malicious-ip?ip=' + ip + '&url=' + url)
                icap_response.send_headers(False)
                return True

    return False
