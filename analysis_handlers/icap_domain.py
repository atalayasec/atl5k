import redis

import deepint
from config import get_config
from util.flask import get_host

config = get_config()
whitelist = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=3)


def check_domain_quality(url, memory_cache, logger, cache, pass_mode, icap_response):

    # handle in memory cache
    if url in memory_cache:
        quality = memory_cache.get(url)
    # in memory_cache not found, check redis cache
    else:
        logger.info("MISS from in-memory cache {}".format(url))
        quality = cache.get(url)
    if not quality:
        logger.info("MISS from cache")
        quality = deepint.checkDomain(url)
        cache.setex(url, config['local_cache_expiration_seconds'], quality)
        memory_cache[url] = quality

    if quality == 'suspicious':
        if pass_mode:
            logger.info('Url {0} is malicious, pass'.format(url))
        else:
            logger.info('Url {0} is malicious, block'.format(url))
            icap_response.set_icap_response(200)
            icap_response.set_enc_status('HTTP/1.1 307 Temporary Redirect')
            icap_response.set_enc_header('location', get_host() + '/malicious-domain?domain=' +
                                         deepint.getFQDN(url) + '&url=' + url)
            icap_response.send_headers(False)
            return True

    return False
