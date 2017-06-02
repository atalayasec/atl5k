from multiprocessing import Process

import deepint
from config import get_config
from util.flask import get_host

config = get_config()
quarantine_page_url = '/quarantine'
malicious_file_url = '/malicious-file'


def check_file_quality(icap_response, logger, pass_mode, cache):
    body = ''
    chunks = []
    proxy_url = get_host()

    while True:
        chunk = icap_response.read_chunk()
        if len(chunks) == 0:
            if not deepint.checkMagic(chunk):
                icap_response.one_chunk_off(chunk)
                return
        if chunk == '':
            break
        else:
            chunks.append(chunk)
            body += chunk

    if deepint.checkMagic(body):

        file_extension = ''
        try:
            s = icap_response.enc_req[1]
            file_extension = s.split('.')[len(s.split('.')) - 1]
        except Exception as e:
            print(e)
            pass

        md5 = deepint.md5(body)

        quality = cache.get(md5)
        if not quality:
            quality = deepint.checkMD5(md5)
            if quality != 'unknown':
                cache.setex(md5, config['local_cache_expiration_seconds'],
                            quality)

        if quality == 'malicious':
            if pass_mode:
                logger.info('File {0} is malicious, pass'.format(md5))
            else:
                logger.info('File {0} is malicious, block'.format(md5))
                icap_response.set_icap_response(200)
                icap_response.set_enc_status('HTTP/1.1 307 Temporary Redirect')
                icap_response.set_enc_header('location',
                                             proxy_url + malicious_file_url +
                                             '?md5=' + deepint.md5(body))
                icap_response.send_headers(False)
                return

        elif quality == 'clean':
            icap_response.set_icap_response(200)
            icap_response.set_enc_status('HTTP/1.1 307 Temporary Redirect')
            test = proxy_url + '/static/tmp/' + deepint.writePayload(
                body, file_extension)
            icap_response.set_enc_header('location', test)

            icap_response.send_headers(False)
            return True

        elif quality == 'unknown':
            file_name = deepint.writePayload(body, file_extension)
            try:
                handle_file_upload(file_name, body)

            except Exception as e:
                print('er- ' + e)

            icap_response.set_icap_response(200)
            icap_response.set_enc_status('HTTP/1.1 307 Temporary Redirect')
            icap_response.set_enc_header(
                'location', proxy_url + quarantine_page_url + '?md5=' + md5 +
                '&filename=' + file_name)
            icap_response.send_headers(False)

            return True
        else:
            raise Exception('Wrong classification')
    icap_response.body_scanned(chunks)
    return False


def handle_file_upload(file_name, body):
    p = Process(target=deepint.upload_file, args=(file_name, body))
    p.start()
    return
