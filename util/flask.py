import os
import json
import redis
import subprocess
from subprocess import CalledProcessError
import netifaces as ni
from config import get_config

config = get_config()
live_config = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=1)
local_path = os.path.dirname(os.path.abspath(__file__))
arguments_file_path = '/tmp/host_configuration.json'


def reload_host_configuration(new_config):
    old_config = get_host_configuration()

    if 'HTTPSCertificate' not in new_config and 'HTTPSCertificate' in old_config:
        new_config['HTTPSCertificate'] = None

    live_config.set('proxy_mode', new_config['proxyMode'])
    live_config.set('upload_file_if_unknown', new_config['suricata_upload_mode'])
    live_config.set('iptables_forward_enabled', new_config['iptables_forward_enabled'])
    live_config.set('virustotal_api_key', new_config['virustotal_api_key'])
    live_config.set('safebrowsing_api_key', new_config['safebrowsing_api_key'])

    configs = {
        'new': new_config,
        'old': old_config,
        'mode': 'complete_reload'
    }

    # save args to an arbitrary file
    args_file = open(arguments_file_path, 'w+')
    json.dump(configs, args_file)
    args_file.close()

    # run the script that need sudo
    root_script = '/root/configure_host.py'
    subprocess.Popen(['/usr/bin/sudo', '/usr/bin/python', root_script])

    # writing new configuration to save configuration file
    host_file = open(local_path + '/../' + config['host_configuration_file'], 'w+')
    json.dump(new_config, host_file)
    host_file.close()


def get_host_configuration():
    conf = {}

    conf['virustotal_api_key'] = live_config.get('virustotal_api_key')
    conf['safebrowsing_api_key'] = live_config.get('safebrowsing_api_key')
    conf['sandbox_username'] = live_config.get('sandbox_username')
    conf['sandbox_password'] = live_config.get('sandbox_password')
    conf['syslogEnabled'] = live_config.get("syslogEnabled") not in [None, "False"]
    conf['syslogHost'] = live_config.get("syslogHost")
    conf['syslogPort'] = live_config.get("syslogPort")
    conf["sslBump"] = live_config.get("sslBump") not in [None, "False"]

    # eth0
    try:
        eth0_info = ni.ifaddresses('eth0')

        conf['eth0_dhcp_enabled'] = os.path.isfile('/var/lib/dhcp/dhclient.eth0.leases')
        try:
            conf['eth0_ip'] = eth0_info[2][0]['addr']
            conf['eth0_netmask'] = eth0_info[2][0]['netmask']
        except KeyError:
            conf['eth0_ip'] = None
            conf['eth0_netmask'] = None

        try:
            conf['eth0_gw'] = ni.gateways()['default'][2][0]
        except KeyError:
            conf['eth0_gw'] = None

    except ValueError:
        pass

    # eth1
    try:
        eth1_info = ni.ifaddresses('eth1')

        if len(eth1_info) < 3:
            conf['eth1_has_addr'] = False
        else:
            conf['eth1_has_addr'] = True
            try:
                conf['eth1_ip'] = eth1_info[2][0]['addr']
                conf['eth1_netmask'] = eth1_info[2][0]['netmask']
            except KeyError:
                conf['eth1_ip'] = None
                conf['eth1_netmask'] = None

            try:
                conf['eth1_gw'] = ni.gateways()['default'][2][0]
            except KeyError:
                conf['eth1_gw'] = None

    except ValueError:
        pass

    try:
        conf['proxyEnabled'] = subprocess.check_output(['pidof', 'squid']) != ''
    except CalledProcessError:
        conf['proxyEnabled'] = False

    # TODO: refactor this porting all to redis and init.py
    try:
        host_file = open(local_path + '/../' + config['host_configuration_file'], 'r')
        saved_conf = json.load(host_file)
        host_file.close()

        for key in ['HTTPSEnabled', 'HTTPSCertificate', 'proxyMode']:
            try:
                conf[key] = saved_conf[key]
            except KeyError:
                conf[key] = None

    except IOError:
        conf['HTTPSEnabled'] = conf['HTTPSCertificate'] = None

    try:
        conf['suricataEnabled'] = subprocess.check_output(['pidof', 'suricata']) != ''
    except CalledProcessError:
        conf['suricataEnabled'] = False

    conf['suricata_upload_mode'] = live_config.get('upload_file_if_unknown') == 'True'
    conf['iptables_forward_enabled'] = live_config.get('iptables_forward_enabled') == 'True'
    conf['proxyPort'] = live_config.get('proxy_port')

    dns_resolvers = get_resolvers()

    if len(dns_resolvers) >= 1:
        conf['dns1'] = dns_resolvers[0]
    else:
        conf['dns1'] = None

    if len(dns_resolvers) >= 2:
        conf['dns2'] = dns_resolvers[0]
    else:
        conf['dns2'] = None

    f = open('/proc/cmdline')
    tmp = f.read()

    conf['live'] = 'boot=live' in tmp

    return conf


def get_host():
    try:
        eth0_info = ni.ifaddresses('eth0')
        return 'http://' + eth0_info[2][0]['addr']
    except Exception:
        return 'http://localhost:5000'


def renew_dhcp(interface):
    args = {
        'mode': 'renew_dhcp',
        'interface': interface
    }

    # save args to an arbitrary file
    args_file = open(arguments_file_path, 'w+')
    json.dump(args, args_file)
    args_file.close()

    # run the script that need sudo
    root_script = '/root/configure_host.py'
    subprocess.Popen(['/usr/bin/sudo', '/usr/bin/python', root_script])


def get_resolvers():
    resolvers = []
    try:
        with open('/etc/resolv.conf', 'r') as resolvconf:
            for line in resolvconf.readlines():
                if 'nameserver' in line:
                    resolvers.append(line.split(' ')[1].strip())
        return resolvers
    except IOError as error:
        return error.strerror


def launch_install_script():
    result = subprocess.call(['/usr/bin/sudo', '/bin/bash', '/root/installer.sh'])
    live_config.set('installation', result)
