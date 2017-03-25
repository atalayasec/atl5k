import deepint
from config import get_config
from urlparse import urlparse

config = get_config()


def handle(domain, logger, cache,memory_cache):
    #we expect a clean domain here, but just in case we are given for a URL we extract the domain
    
    
    logger.info('SDH Checking domain {0}'.format(domain))

    quality=deepint.domain_cache(domain,logger,cache,memory_cache)
    from_cache = True

    if not quality:
        quality = deepint.checkDomain(domain)
        from_cache = False 

    from_cache_message = ', from cache' if from_cache else ''

    if quality == 'suspicious':
        logger.info('SDH Domain {0} is suspicious{1}'.format(domain, from_cache_message))

    elif quality == 'clean':
        logger.info('SDH Domain {0} is clean{1}'.format(domain, from_cache_message))

    else:
        logger.info('SDH Domain {0} is unknown'.format(domain))

    if not from_cache and quality != 'unknown':
        cache.setex(domain, config['local_cache_expiration_seconds'], quality)
