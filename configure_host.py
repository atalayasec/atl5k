import os
import json
import subprocess
import netifaces as ni
from jinja2 import Environment, FileSystemLoader

DHCP_ETH0_LEASE = '/var/lib/dhcp/dhclient.eth0.leases'
DHCP_ETH1_LEASE = '/var/lib/dhcp/dhclient.eth1.leases'
TEMPLATES_PATH = '/var/atl5k/templates/'

loader = FileSystemLoader(TEMPLATES_PATH)
env = Environment(loader=loader)
interfaces_template = template = env.get_template('interfaces')


class DictDiffer(object):
    """
    Calculate the difference between two dictionaries as:
    (1) items added
    (2) items removed
    (3) keys same in both but changed values
    (4) keys same in both and unchanged values
    """

    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.set_current, self.set_past = set(current_dict.keys()), set(past_dict.keys())
        self.intersect = self.set_current.intersection(self.set_past)

    def added(self):
        return self.set_current - self.intersect

    def removed(self):
        return self.set_past - self.intersect

    def changed(self):
        return set(o for o in self.intersect if self.past_dict[o] != self.current_dict[o])

    def unchanged(self):
        return set(o for o in self.intersect if self.past_dict[o] == self.current_dict[o])


def restart_squid():
    subprocess.Popen(['/bin/systemctl', 'restart', 'squid'])


def ifdown(interface):
    subprocess.call(['ifdown', interface])


def ifup(interface):
    subprocess.call(['ifup', interface])


def reload_complete_configuration(old_config, new_config):

    ifdown('eth0')
    ifdown('eth1')

    network = {
        'eth0': {},
        'eth1': {},
        'dns1': new_config['dns1'],
        'dns2': new_config['dns2']
    }

    if network['dns1'] == '...':
        network['dns1'] = False

    if network['dns2'] == '...':
        network['dns2'] = False

    if new_config['eth0_dhcp_enabled']:
        network['eth0']['static'] = False
    else:
        network['eth0'] = {
            'static': True,
            'ip': new_config['eth0_ip'],
            'netmask': new_config['eth0_netmask'],
            'gateway': new_config['eth0_gateway']
        }

    if not new_config['eth1_has_addr']:
        network['eth1']['has_addr'] = False
    else:
        network['eth1'] = {
            'has_addr': True,
            'static': True,
            'ip': new_config['eth1_ip'],
            'netmask': new_config['eth1_netmask'],
            'gateway': new_config['eth1_gateway']
        }

    f = open('/etc/network/interfaces', 'w')
    f.write(interfaces_template.render(**network))
    f.close()

    if not new_config['eth0_dhcp_enabled'] and os.path.exists(DHCP_ETH0_LEASE):
        os.remove(DHCP_ETH0_LEASE)

    ifup('eth0')
    ifup('eth1')

    diff = DictDiffer(old_config, new_config)
    changes = diff.changed()

    # suricata handling
    if 'suricataEnabled' in changes:
        if new_config['suricataEnabled']:
            subprocess.call(['/bin/systemctl', 'start', 'suricata'])
        else:
            subprocess.call(['/bin/systemctl', 'stop', 'suricata'])
    squid_already_enabled = False



    # iptables handling
    if 'iptables_forward_enabled' in changes:
        if new_config['iptables_forward_enabled']:
            subprocess.call(['/sbin/iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'])
            subprocess.call(['/sbin/iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', 'eth1', '-m', 'state', '--state',
                             'NEW,RELATED,ESTABLISHED', '-j', 'ACCEPT'])
            subprocess.call(['/sbin/iptables', '-A', 'FORWARD', '-i', 'eth1', '-o', 'eth0', '-j', 'ACCEPT'])
        else:
            subprocess.call(['/sbin/iptables', '-t', 'nat', '-F'])
            subprocess.call(['/sbin/iptables', '-F'])


    # squid handling
    if 'proxyPort' in changes or 'HTTPSEnabled' in changes or 'HTTPSCertificate' in changes:
        if 'HTTPSCertificate' in changes and new_config['HTTPSCertificate']:
            certificate = new_config['HTTPSCertificate']
            cert = open('/etc/ssl/cert.pem', 'w')
            cert.write(certificate)
            cert.close()
        else:
            certificate = old_config['HTTPSCertificate']

        eth0_address = ni.ifaddresses('eth0')[2][0]['addr']

        squid_base_config = """
http_access allow ALL
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Authenticated-User
icap_preview_enable on
icap_preview_size 1024
icap_service service_resp respmod_precache icap://127.0.0.1:13440/response
adaptation_access service_resp allow all
visible_hostname {0}\n""".format(eth0_address)

        if 'HTTPSEnabled' in new_config and new_config['HTTPSEnabled']:
            squid_base_config += 'https_port ' + new_config['proxyPort'] + ' cert=/etc/ssl/cert.pem\n'
        else:
            squid_base_config += 'http_port ' + new_config['proxyPort'] + '\n'

        squid = open('/etc/squid/squid.conf', 'w')
        squid.write(squid_base_config)
        squid.close()

        if new_config['proxyEnabled']:
            restart_squid()
            squid_already_enabled = True

    if 'proxyEnabled' in changes:
        if new_config['proxyEnabled']:
            if not squid_already_enabled:
                restart_squid()
        else:
            subprocess.Popen(['/bin/systemctl', 'stop', 'squid'])


def renew_dhcp_lease(interface):
    ifdown(interface)

    lease_file = '/var/lib/dhcp/dhclient.{0}.leases'.format(interface)

    if os.path.exists(lease_file):
        os.remove(lease_file)

    ifup(interface)


if __name__ == '__main__':
    args_file_absolute_path = '/tmp/host_configuration.json'

    args_file = open(args_file_absolute_path, 'r')
    args = json.load(args_file)
    args_file.close()
    os.remove(args_file_absolute_path)

    if 'mode' in args:
        if args['mode'] == 'renew_dchp':
            # need only to re-enable dhcp to take new lease
            renew_dhcp_lease(args['interface'])
            pass
        elif args['mode'] == 'complete_reload':
            reload_complete_configuration(args['old'], args['new'])
    else:
        # by default reload everything, done mainly for compatibility reasons
        reload_complete_configuration(args['old'], args['new'])
