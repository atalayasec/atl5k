import deepint
from config import get_config

config = get_config()


def handle(ip, logger, cache, memory_cache):

    quality = cache.get(ip)
    from_cache = True

    if not quality:
        quality = deepint.checkIP(ip)
        from_cache = False

    from_cache_message = ', from cache' if from_cache else ''

    if quality == 'suspicious':
        logger.info('IP {0} is suspicious{1}'.format(ip, from_cache_message))

    elif quality == 'clean':
        logger.info('IP {0} is clean{1}'.format(ip, from_cache_message))

    else:
        logger.info('IP {0} is unknown'.format(ip))

    if not from_cache and (quality == 'suspicious' or quality == 'clean'):
        cache.setex(ip, config['local_cache_expiration_seconds'], quality)
