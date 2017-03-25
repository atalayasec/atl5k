import deepint
import re


META_HOST='HTTP HOST: *(?P<domain>[a-zA-Z0-9\-\.\_]+)'

def parsefilemeta(path):
    x=re.compile(META_HOST)
    fd = open(path+'.meta', 'r')
    for l in fd:
        m=x.match(l)
        if m:
            return m.group('domain')
    f.close()



def handle(md5string, event, logger,cache,memory_cache, upload_mode=False):
    domain=parsefilemeta(event.pathname)
    
    quality=deepint.domain_cache(domain,logger,cache,memory_cache)


    if quality is not 'clean':
        logger.info('Checking File {0} as domain {1} is not clean'.format(event.name,domain))
        filecache = cache.get(md5)
        if filecache:
            logger.info('File {0} quality information taken from local cache'.format(md5))
        else:
            quality = deepint.checkMD5(md5string)
            if quality != 'unknown':
                cache.setex(md5, config['local_cache_expiration_seconds'], quality)
    if quality == 'malicious':
        logger.info('File {0} is malicious'.format(event.name))
    elif quality == 'clean':
        logger.info('File {0} is clean'.format(event.name))
    elif quality == 'unknown':
        logger.info('File {0} is unknown to the sandbox'.format(event.name))
        if upload_mode is True:
            fd = open(event.pathname, 'r')
            print(deepint.upload_file(event.name, fd.read()))
