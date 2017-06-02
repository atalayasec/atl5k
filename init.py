import redis

from config import get_config
from util.postgres import init_db

config = get_config()
init_db()

live_config = redis.StrictRedis(
    host=config['redis_host'], port=config['redis_port'], db=1)
live_config.set('upload_file_if_unknown', 'False')
live_config.set('virustotal_api_key', '')
live_config.set('safebrowsing_api_key', '')
live_config.set('sandbox_username', '')
live_config.set('sandbox_password', '')
live_config.set('proxy_port', '3128')
live_config.set('iptables_forward_enabled', 'False')
