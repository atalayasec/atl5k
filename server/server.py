import logging
import sys
from threading import Thread
import redis
from flask import Flask, render_template, flash, request, session, redirect
import requests
from phishtank import PhishTank

from authentication import check_credentials, login_required, change_password
from config import get_config
from logger.search import *
from util.flask import *

CENSORED = "*****"

root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

config = get_config()
app = Flask(__name__)
app.secret_key = 'very_secret_key'

app.config["PROPAGATE_EXCEPTIONS"] = True

white_ip = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=2)
white_domain = redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=3)
ALLOWED_EXTENSIONS = {'crt', 'cer', 'csr'}

phishtank = PhishTank(redis.StrictRedis(host=config['redis_host'], port=config['redis_port'], db=4), live_config)
phishtank.daemon = True
phishtank.start()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/quarantine')
def quarantine_page():
    return render_template('light/quarantine.html'), 200


@app.route('/malicious-domain')
def malicious_domain_page():
    domain = request.args.get('domain')
    request_url = request.args.get('url')
    return render_template('light/malicious_domain.html', domain=domain, request_url=request_url), 200


@app.route('/malicious-ip')
def malicious_ip_page():
    ip = request.args.get('ip')
    request_url = request.args.get('url')
    return render_template('light/malicious_ip.html', ip=ip, request_url=request_url), 200


@app.route('/malicious-file')
def malicious_file_page():
    return render_template('light/malicious_file.html'), 200


@app.route('/whitelist/ip', methods=["POST"])
def whitelist_ip():
    ip = request.form.get('ip')
    white_ip.set(ip, True)
    return 'whitelisted ' + ip, 200


@app.route('/whitelist/domain', methods=["POST"])
def whitelist_domain():
    domain = request.form.get('domain')
    white_domain.set(domain, True)
    return 'whitelisted ' + domain, 200


@app.route("/check")
def check():
    md5 = request.args.get('md5')

    class R(object):
        status = "SANDBOX_STATUS_FAKE"
        msg = {
            "classification": {
                "result": "Clean"
            }
        }
    result = R()
    print(result.status)
    print(result.msg['classification'])

    if result.status == 'SANDBOX_STATUS_CLIENT_ERROR' or result.status == 'SANDBOX_STATUS_PROCESSING':
        # uploaded but still processing
        return 'checking', 202
    elif result.msg['classification']['result'] == "Malicious":
        # uploaded, processed and malicious
        return 'malicious', 200
    elif result.msg['classification']['result'] == "Clean":
        # uploaded, processed and clean
        return 'clean', 200


# ADMIN
@app.route('/')
@login_required
def render_admin():

    network_data = {
        'blocked_ips': get_blocked_ips_24(),
        'blocked_domains': get_blocked_domains_24(),
        'blocked_files': get_blocked_files_24()
    }

    resp = requests.get("http://127.0.0.1:8080/credentials")
    try:
        configured_analysers = resp.json().get("result")
    except:
        configured_analysers = []

    host_cfg = get_host_configuration()
    if "cuckoo" in configured_analysers:
        host_cfg['sandbox_username'] = CENSORED
        host_cfg['sandbox_password'] = CENSORED
    if "virustotal" in configured_analysers:
        host_cfg['virustotal_api_key'] = CENSORED
    if host_cfg.get("safebrowsing_api_key"):
        host_cfg["safebrowsing_api_key"] = CENSORED
    if host_cfg.get("phishtank_api_key"):
        host_cfg["phishtank_api_key"] = CENSORED

    return render_template('admin/main.html',
                           host_configuration=host_cfg,
                           network_data=network_data
                           ), 200


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('admin/login.html'), 200
    elif request.method == 'POST':
        try:
            user = request.form['username']
            password = request.form['md5password']

            if check_credentials(user, password):
                session['user'] = user
                return redirect('/')
            else:
                return render_template('admin/login.html', error='invalid_credentials')
        except KeyError as e:
            return render_template('admin/login.html', error='wrong_parameters')


@app.route('/httpscert', methods=['GET'])
def get_http_certificate():
    try:
        cert = open('/etc/ssl/cert.pem')
        content = cert.read()
        cert.close()
        return content, 200
    except Exception:
        return '', 404


@app.route('/logs', methods=['GET'])
@login_required
def search_log():
    string = request.args.get('string')
    f = request.args.get('from')
    t = request.args.get('to')

    try:
        return json.dumps(logs_generic_search(string=string, start=f, stop=t)), 200
    except Exception as e:
        print e
        return 500


@app.route('/search-in-logs', methods=['GET'])
@login_required
def render_search_log_page():
    return render_template('admin/search-logs.html'), 200


@app.route('/configuration', methods=['POST'])
@login_required
def save_configuration():
    # sanitizing form data
    try:
        new_config = {
            'eth0_dhcp_enabled': 'eth0_dhcp' in request.form and request.form['eth0_dhcp'] == 'on',
            'eth1_has_addr': 'eth1_has_addr' in request.form and request.form['eth1_has_addr'] == 'on',
            'suricataEnabled': 'suricataOnOff' in request.form and request.form['suricataOnOff'] == 'on',
            'suricata_upload_mode': 'suricata_upload_mode' in request.form and request.form['suricata_upload_mode'] == 'on',
            'iptables_forward_enabled': 'iptables_forward_enabled' in request.form and request.form['iptables_forward_enabled'] == 'on',
            'proxyEnabled': 'proxyOnOff' in request.form and request.form['proxyOnOff'] == 'on',
            'HTTPSEnabled': 'proxyHTTPS' in request.form and request.form['proxyHTTPS'] == 'on',
            'virustotal_api_key': request.form['virustotal_api_key'],
            'safebrowsing_api_key': request.form['safebrowsing_api_key'],
            'sandbox_username': request.form['sandbox_username'],
            'sandbox_password': request.form['sandbox_password'],
            'phishtank_api_key': request.form['phishtank_api_key'],
            'phishtank_update_delay': request.form['phishtank_update_delay'],
            'proxyPort': request.form['proxyPort'] if request.form['proxyPort'] else 3128,
            'proxyMode': request.form['proxyMode']
        }

        live_config["sslBump"] = "sslBump" in request.form and request.form['sslBump'] == "on"
        new_config["sslBump"] = live_config["sslBump"]

        # handling eth0
        if not new_config['eth0_dhcp_enabled']:
            new_config['eth0_ip'] = request.form['eth0_ip_1'] + '.' + request.form['eth0_ip_2'] + \
                                    '.' + request.form['eth0_ip_3'] + '.' + request.form['eth0_ip_4']
            new_config['eth0_netmask'] = request.form['eth0_nm_1'] + '.' + request.form['eth0_nm_2'] + \
                                         '.' + request.form['eth0_nm_3'] + '.' + request.form['eth0_nm_4']
            new_config['eth0_gateway'] = request.form['eth0_gw_1'] + '.' + request.form['eth0_gw_2'] + \
                                         '.' + request.form['eth0_gw_3'] + '.' + request.form['eth0_gw_4']

        # handling eth1
        if new_config['eth1_has_addr']:
            new_config['eth1_ip'] = request.form['eth1_ip_1'] + '.' + request.form['eth1_ip_2'] + \
                                    '.' + request.form['eth1_ip_3'] + '.' + request.form['eth1_ip_4']
            new_config['eth1_netmask'] = request.form['eth1_nm_1'] + '.' + request.form['eth1_nm_2'] + \
                                         '.' + request.form['eth1_nm_3'] + '.' + request.form['eth1_nm_4']
            new_config['eth1_gateway'] = request.form['eth1_gw_1'] + '.' + request.form['eth1_gw_2'] + \
                                         '.' + request.form['eth1_gw_3'] + '.' + request.form['eth1_gw_4']

        new_config['dns1'] = request.form.get('dns1-1', "") + '.' + request.form.get('dns1-2', "") + \
                             '.' + request.form.get('dns1-3', "") + '.' + request.form.get('dns1-4', "")
        new_config['dns2'] = request.form.get('dns2-1', "") + '.' + request.form.get('dns2-2', "") + \
                             '.' + request.form.get('dns2-3', "") + '.' + request.form.get('dns2-4', "")

        syslogEnabled = request.form.get("syslogEnabled")
        syslogHost = request.form.get("syslogHost", None)
        syslogPort = request.form.get("syslogPort", None)
        if syslogEnabled:
            # install and restart syslogng configuration
            live_config["syslogEnabled"] = True
            live_config["syslogPort"] = syslogPort
            live_config["syslogHost"] = syslogHost
        else:
            live_config["syslogEnabled"] = False

        live_config["phishtank_api_key"] = request.form.get("phishtank_api_key", None)
        live_config["phishtank_update_delay"] = request.form.get("phishtank_update_delay", -1)
        root.info("configured phishtank with api {}... delay {}".format(
            request.form.get("phishtank_api_key")[:5],
            request.form.get("phishtank_update_delay")
        ))

        # handling HTTPS certificate case
        if 'HTTPSCertificate' in request.files:
            certificate = request.files['HTTPSCertificate']
            if allowed_file(certificate.filename):
                new_config['HTTPSCertificate'] = certificate.read()

        root.info(new_config)
        reload_host_configuration(new_config)
        # FIXME: with current configuration EVERYTHING is hardcoded
        msg = 'Configuration saved successfully!'

        # do not run the post if the config has not changed
        old_vtak = config.get("virustotal_api_key")
        old_cu = config.get("sandbox_username")
        old_cp = config.get("sandbox_password")
        new_vtak = new_config.get("virustotal_api_key")
        new_cu = new_config.get("sandbox_username")
        new_cp = new_config.get("sandbox_password")
        if old_vtak != new_vtak or old_cu != new_cu or old_cp != new_cp:
            resp = requests.post("http://127.0.0.1:8080/credentials",
                                 headers={"Content-Type": "application/json"},
                                 data=json.dumps({
                                     "virustotal_api_key": new_vtak,
                                     "sandbox_username": new_cu,
                                     "sandbox_password": new_cp
                                 }))
            if resp.status_code != 200:
                msg += "API key or username/password not saved, error: {}".format(resp.json().get("result"))
            else:
                msg += "API key or username/password updated"
        flash(msg, 'success')
        return redirect('/')

    except Exception as e:
        root.debug(e)
        return '{0}'.format(e), 400


@app.route('/renew-dhcp', methods=['GET'])
@login_required
def new_dhcp():
    interface = request.args.get('interface')
    try:
        renew_dhcp(interface)
        return 'ok', 200
    except Exception as e:
        root.debug(e)
        return '{0}'.format(e), 400


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_user_password():
    if request.method == 'GET':
        return render_template('/admin/user-details.html'), 200
    elif request.method == 'POST':
        new = request.form['md5password']
        confirm = request.form['md5confirm']

        if new != confirm:
            flash('The two password don\'t match!', 'error')
            return render_template('/admin/user-details.html'), 200
        else:
            change_password(new)
            flash('Password changed correctly.', 'success')
            return render_admin()


@app.route('/install', methods=['GET', 'POST'])
@login_required
def install():
    if request.method == 'GET':
        exit_code = live_config.get('installation')

        if exit_code is not None:
            if int(exit_code) == 0:
                result = 'success'
            else:
                result = 'error'
        else:
            result = 'running'

        return result, 200

    else:
        try:
            p = Thread(target=launch_install_script, args=[])
            p.start()
            return 'ok', 200
        except Exception as e:
            return str(e), 500

if __name__ == "__main__":
    app.run(debug=True)
