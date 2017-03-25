import redis

import deepint
from config import get_config
from util.flask import get_host

config = get_config()
whitelist = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=3)


def check_domain_quality(url, memory_cache, logger, cache, pass_mode, icap_response):

    domain = deepint.getFQDN(url)

    # checking for domain in whitelist
    is_whitelisted = whitelist.get(domain)
    if is_whitelisted:
        pass
    else:
        # handle in memory cache
        if domain in memory_cache:
            quality = memory_cache.get(domain)
        # in memory_cache not found, check redis cache
        else:
            quality = cache.get(domain)
        if not quality:
            quality = deepint.checkDomain(domain)
            cache.setex(domain, config['local_cache_expiration_seconds'], quality)
            memory_cache[domain] = quality

        if quality == 'suspicious':
            if pass_mode:
                logger.info('Domain {0} is malicious, pass'.format(domain))
            else:
                logger.info('Domain {0} is malicious, block'.format(domain))
                icap_response.set_icap_response(200)
                icap_response.set_enc_status('HTTP/1.1 307 Temporary Redirect')
                icap_response.set_enc_header('location', get_host() + '/malicious-domain?domain=' +
                                             deepint.getFQDN(url) + '&url=' + url)
                icap_response.send_headers(False)
                return True

    return False
