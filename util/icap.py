#import hashlib

def do_hash(url):
    # make a no-op for compatibility reasons
    #h = hashlib.sha256(url)
    #return h.hexdigest()
    return url
