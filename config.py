import os
import json


def get_config():
    local_path = os.path.dirname(os.path.abspath(__file__))
    config_file = open(local_path + '/config.json')
    config = json.load(config_file)
    config_file.close()
    return config
