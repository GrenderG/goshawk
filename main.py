import datetime
import hashlib
import hmac
import io
import logging
import struct
import time

from Crypto.Cipher import AES
from flask import Flask, send_from_directory, make_response, request

from app.constants import Constants
from app.utils import Utils

app = Flask(__name__)


# ----------------------------------------------------------------------------------------------------------------------
# DLC file routes.

@app.route(f'/{Constants.DIR_WIIU}/<path:path>', methods=['GET'])
def serve_wiiu_dlc_file(path):
    return send_from_directory(f'files/{Constants.DIR_WIIU}', path,
                               mimetype='Content-Type: text/plain; charset=Shift_JIS')


@app.route(f'/{Constants.DIR_3DS}/<path:path>', methods=['GET'])
def serve_3ds_dlc_file(path):
    return send_from_directory(f'files/{Constants.DIR_3DS}', path,
                               mimetype='Content-Type: text/plain; charset=Shift_JIS')


@app.route(f'/{Constants.DIR_P01}/<path:path>', methods=['GET'])
def serve_airu_dlc_file(path):
    return send_from_directory(f'files/{Constants.DIR_P01}', path)


# ----------------------------------------------------------------------------------------------------------------------
# Login CGI routes.

# v1
def make_login_v1_response(key, system_dir='', game_dir='', server_url=Constants.BASE_SERVER_URL):
    # This format is used for 3G/3U, 4, 4G/4U:
    # - key length (short, big-endian).
    # - key bytes, null terminated.
    # - url length (short, big-endian).
    # - url bytes, not null terminated.

    key_bytes = key.encode('shift_jis') + b'\x00'
    key_length_bytes = len(key_bytes).to_bytes(2, 'big')
    # URL string is not null terminated.
    url_bytes = server_url.encode('shift_jis') + system_dir.encode('shift_jis') + game_dir.encode('shift_jis')
    url_length_bytes = len(url_bytes).to_bytes(2, 'big')

    response_bytes = key_length_bytes + key_bytes + url_length_bytes + url_bytes
    response = make_response(response_bytes)

    # Remove Content-Type header since original servers are not sending it.
    response.headers.remove('Content-Type')

    return response


# v3.
# See https://github.com/svanheulen/mhff/wiki/MHX-DLC-Key-Negotiation for protocol references.
def make_login_v3_response(key, rsa_pub_key, server_url, system_dir='', game_dir=''):
    response_bytes = b''

    try:
        # Request parameters.
        # - char protocol_version = 3(or 4);
        # - char len;
        # - char service_locator_data[len];
        # - int unknown = 1;
        # - int unknown = 0;
        # - int unknown = 0;
        # - short unknown = 0;
        # - byte unknown = 0; (In, protocol_version 4,  short unknown)
        # - int client_nonce;
        # - char client_hmac[32];

        data = request.data
        byte_stream = io.BytesIO(data)
        protocol_version = int.from_bytes(byte_stream.read(1), 'big')
        service_locator_len = int.from_bytes(byte_stream.read(1), 'big')
        service_locator = byte_stream.read(service_locator_len).decode()
        unk1 = int.from_bytes(byte_stream.read(4), 'big')
        unk2 = int.from_bytes(byte_stream.read(4), 'big')
        unk3 = int.from_bytes(byte_stream.read(4), 'big')
        unk4 = int.from_bytes(byte_stream.read(2), 'big')
        unk5 = None
        if protocol_version == 3:
            unk5 = int.from_bytes(byte_stream.read(1), 'big')
        else:
            unk5 = int.from_bytes(byte_stream.read(2), 'big')
        client_nonce = byte_stream.read(4)
        client_hmac = byte_stream.read(32)

        # Decode the service_locator token and get the userid. In the current implementation, only userid is contained.
        userid = int(Utils.b64decode(service_locator))
        uid = struct.pack('>I', userid)

        # Verification client hmac.
        '''
        client_hmac_key  = hashlib.sha256(uid + client_nonce).digest()
        h = hmac.new(client_hmac_key, data[:-32], hashlib.sha256)
        if h.hexdigest() != client_hmac:
            logging.error('error! client hmac is the not same')
        '''

        # Response parameters.
        # - short b_key_len;
        # - char encrypted_blowfish_key[b_key_len];
        # - short r_key_len;
        # - char rsa_pubkey[r_key_len];
        # - short url_len;
        # - char dlc_url[url_len];
        # - int server_nonce;
        # - char server_hmac[32];

        server_nonce = int(time.time())
        server_nonce_bytes = server_nonce.to_bytes(4, 'big')

        aes_key = uid + client_nonce + server_nonce_bytes + uid
        iv = 16 * b'\0'
        aes = AES.new(aes_key, AES.MODE_CBC, iv)
        b_key = aes.encrypt(key)
        b_key_len = len(b_key).to_bytes(2, 'big')
        r_key_len = len(rsa_pub_key).to_bytes(2, 'big')
        url_bytes = server_url.encode('shift_jis') + system_dir.encode('shift_jis') + game_dir.encode('shift_jis')
        url_len = len(url_bytes).to_bytes(2, 'big')
        client_hmac_key = hashlib.sha256(uid + client_nonce + server_nonce_bytes).digest()
        response_bytes = b_key_len + b_key + r_key_len + rsa_pub_key + url_len + url_bytes + server_nonce_bytes
        hs = hmac.new(client_hmac_key, response_bytes, hashlib.sha256)
        server_hmac = hs.digest()

        response_bytes += server_hmac
    except Exception as e:
        logging.error(e)

    response = make_response(response_bytes)
    # Remove Content-Type header since original servers are not sending it.
    response.headers.remove('Content-Type')
    return response


# 3G JAP.

@app.route('/SSL/3ds/mh3g/login.cgi', methods=['POST'])
def login_mh3g():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/mh3g/')


# 3U EUR.

@app.route('/SSL/3ds/mh3gu_eu/login.cgi', methods=['POST'])
def login_mh3gu_eu():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/mh3gu_eu/')


@app.route('/SSL/wiiu/mh3gu_eu/login.cgi', methods=['POST'])
def login_mh3ghd_eu():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_WIIU, '/mh3ghd_eu/')


# 3U USA.

@app.route('/SSL/3ds/mh3gu_us/login.cgi', methods=['POST'])
def login_mh3gu_us():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/mh3gu_us/')


@app.route('/SSL/wiiu/mh3gu_us/login.cgi', methods=['POST'])
def login_mh3ghd_us():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_WIIU, '/mh3ghd_us/')


# 3U KOR.

@app.route('/SSL/3ds/mh3gu_kor/login.cgi', methods=['POST'])
def login_mh3gu_kor():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/mh3gu_kor/')


# ----------------------------------------------------------------------------------------------------------------------
# 4 JAP.

@app.route('/SSL/3ds/mh4/login.cgi', methods=['POST'])
def login_mh4():
    # Original server is not sending the URL for MH4 JP.
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, server_url='')


# 4 KOR.

@app.route('/SSL/3ds/mh4_kor/login.cgi', methods=['POST'])
def login_mh4_kor():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/mh4_kor/')


# 4 TWN.

@app.route('/SSL/3ds/mh4_tw/login.cgi', methods=['POST'])
def login_mh4_tw():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/mh4_tw/')


# ----------------------------------------------------------------------------------------------------------------------
# 4G JAP.

@app.route('/SSL/3ds/mh4g_nihon/login.cgi', methods=['POST'])
def login_mh4g_nihon():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_2, Constants.DIR_3DS, '/mh4g_nihon/')


# 4U EUR.

@app.route('/SSL/3ds/mh4g_eu_/login.cgi', methods=['POST'])
def login_mh4g_eu_():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_2, Constants.DIR_3DS, '/mh4g_eu_/')


# 4U USA.

@app.route('/SSL/3ds/mh4g_us_/login.cgi', methods=['POST'])
def login_mh4g_us_():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_2, Constants.DIR_3DS, '/mh4g_us_/')


# 4G KOR.

@app.route('/SSL/3ds/mh4g_kr_/login.cgi', methods=['POST'])
def login_mh4g_kr_():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_2, Constants.DIR_3DS, '/mh4g_kr_/')


# 4G TWN. This is a special case. Apparently this URL was used in the first versions of the taiwanese version for MH4G
# but was later changed in an update to simply use the JPN one. Adding support for it anyway.

@app.route('/SSL/3ds/redgiant/dl/pro_tw/login.cgi', methods=['POST'])
def login_mh4g_tw():
    return make_login_v1_response(Constants.BLOWFISH_KEY_TYPE_1, Constants.DIR_3DS, '/redgiant/dl/pro_tw/')


# MHX JP

@app.route('/SSL/3ds/mhx/login_new_jp.cgi', methods=['POST'])
def login_mhx_jp():
    return make_login_v3_response(Constants.MHX_JP_KEY + b'\x10' * 0x10, Constants.MHX_PUB_KEY, Constants.X_SERVER_URL,
                                  Constants.DIR_3DS, '/mhx_new_jp/')


# MHX US

@app.route('/SSL/3ds/mhx/login_us.cgi', methods=['POST'])
def login_mhx_us():
    return make_login_v3_response(Constants.MHX_US_KEY + b'\x08' * 0x08, Constants.MHX_PUB_KEY, Constants.X_SERVER_URL,
                                  Constants.DIR_3DS, '/mhx_us/')


# MHX EU

@app.route('/SSL/3ds/mhx/login_eu.cgi', methods=['POST'])
def login_mhx_eu():
    return make_login_v3_response(Constants.MHX_EU_KEY + b'\x08' * 0x08, Constants.MHX_PUB_KEY, Constants.X_SERVER_URL,
                                  Constants.DIR_3DS, '/mhx_eu/')


# MHX TW

@app.route('/SSL/3ds/mhx/login_new_tw.cgi', methods=['POST'])
def login_mhx_tw():
    return make_login_v3_response(Constants.MHXX_JP_KEY + b'\x10' * 0x10, Constants.MHX_PUB_KEY, Constants.X_SERVER_URL,
                                  Constants.DIR_3DS, '/mhx_new_tw/')


# MHXX JP

@app.route('/SSL/3ds/mhxx/login_jp.cgi', methods=['POST'])
def login_mhxx_jp():
    return make_login_v3_response(Constants.MHXX_JP_KEY + b'\x08' * 0x8, Constants.MHXX_PUB_KEY,
                                  Constants.XX_SERVER_URL, Constants.DIR_3DS, '/mhxx_jp/')


# MHXX TW

@app.route('/SSL/3ds/mhxx/login_tw.cgi', methods=['POST'])
def login_mhxx_tw():
    return make_login_v3_response(Constants.MHXX_TW_KEY + b'\x08' * 0x8, Constants.MHXX_PUB_KEY,
                                  Constants.XX_SERVER_URL, Constants.DIR_3DS, '/mhxx_tw/')


# MHST JP

@app.route('/SSL/3ds/mhss/login.cgi', methods=['POST'])
def login_mhst_jp():
    return make_login_v3_response(Constants.MHST_JP_KEY + b'\x08' * 0x08, Constants.MHST_PUB_KEY,
                                  Constants.SS_SERVER_URL, Constants.DIR_3DS, '/mhss_jp/')


# MHST US

@app.route('/SSL/3ds/mhss/login_us.cgi', methods=['POST'])
def login_mhst_us():
    return make_login_v3_response(Constants.MHST_US_KEY + b'\x08' * 0x08, Constants.MHST_PUB_KEY,
                                  Constants.SS_SERVER_URL, Constants.DIR_3DS, '/mhss_us/')


# MHST EU

@app.route('/SSL/3ds/mhss/login_eu.cgi', methods=['POST'])
def login_mhst_eu():
    return make_login_v3_response(Constants.MHST_EU_KEY + b'\x08' * 0x08, Constants.MHST_PUB_KEY,
                                  Constants.SS_SERVER_URL, Constants.DIR_3DS, '/mhss_eu/')


# MHST TW

@app.route('/SSL/3ds/mhss/login_tw.cgi', methods=['POST'])
def login_mhst_tw():
    return make_login_v3_response(Constants.MHST_TW_KEY + b'\x08' * 0x08, Constants.MHST_PUB_KEY,
                                  Constants.SS_SERVER_URL, Constants.DIR_3DS, '/mhss_tw/')


# ----------------------------------------------------------------------------------------------------------------------
# 3DS NASC server.
# https://nasc.nintendowifi.net/ac
def make_nasc_response():
    resp_dict = dict()

    try:
        req = request.form.to_dict()
        action = Utils.b64decode(req['action']).decode()
        if action == 'LOGIN':
            titleid = Utils.b64decode(req['titleid']).decode()
            gameid = Utils.b64decode(req['gameid']).decode()
            # It varies depending on the gameid.
            resp_dict['locator'] = Utils.b64encode('0.0.0.0:0')
            resp_dict['retry'] = Utils.b64encode('0')
            resp_dict['returncd'] = Utils.b64encode('001')
            # Temp value.
            resp_dict['token'] = Utils.b64encode('notActualToken')
            resp_dict['datetime'] = Utils.b64encode(str(datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')))
        elif action == 'SVCLOC':
            userid = Utils.b64decode(req['userid']).decode()
            resp_dict['retry'] = Utils.b64encode('0')
            resp_dict['returncd'] = Utils.b64encode('007')
            # Real server contains more information including userid, friend code and current time with encryption.
            # We currently only need userid.
            resp_dict['servicetoken'] = Utils.b64encode(userid)
            resp_dict['statusdata'] = Utils.b64encode('Y')
            resp_dict['svchost'] = Utils.b64encode('n/a')
            resp_dict['datetime'] = Utils.b64encode(str(datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')))
        else:
            raise ValueError('Unknown action.')
    except Exception as e:
        logging.error(e)

        resp_dict.clear()
        resp_dict['retry'] = Utils.b64encode('1')
        resp_dict['returncd'] = Utils.b64encode('109')
        resp_dict['datetime'] = Utils.b64encode(str(datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')))

    response = make_response(Utils.dict_to_query(resp_dict))
    response.headers['Content-Type'] = 'text/plain;charset=ISO-8859-1'
    return response


@app.route('/ac', methods=['POST'])
def nasc_ac():
    return make_nasc_response()


# http://conntest.nintendowifi.net/
@app.route('/', methods=['GET'])
def conn_test():
    response = send_from_directory('files/conntest', 'test.html')
    response.headers['X-Organization'] = 'Nintendo'
    response.headers['Content-type'] = 'text/html'
    return response


if __name__ == '__main__':
    app.run()
