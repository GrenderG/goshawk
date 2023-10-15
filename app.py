from flask import Flask, send_from_directory, make_response

# Constants.

BASE_SERVER_URL = 'http://goshawk.capcom.co.jp/'
X_SERVER_URL = 'http://spector.capcom.co.jp/'
XX_SERVER_URL = 'http://meteor.capcom.co.jp/'
SS_SERVER_URL = 'http://voodoo.capcom.co.jp/'

DIR_WIIU = 'wiiu'
DIR_3DS = '3ds'

BLOWFISH_KEY_TYPE_1 = 'Capcom123 '
BLOWFISH_KEY_TYPE_2 = 'AgK2DYheaOjyHGP8'

app = Flask(__name__)


# ----------------------------------------------------------------------------------------------------------------------
# DLC file routes.

@app.route(f'/{DIR_WIIU}/<path:path>', methods=['GET'])
def serve_wiiu_dlc_file(path):
    return send_from_directory(DIR_WIIU, path, mimetype='Content-Type: text/plain; charset=Shift_JIS')


@app.route(f'/{DIR_3DS}/<path:path>', methods=['GET'])
def serve_3ds_dlc_file(path):
    return send_from_directory(DIR_3DS, path, mimetype='Content-Type: text/plain; charset=Shift_JIS')


# ----------------------------------------------------------------------------------------------------------------------
# Login CGI routes.
# Note: We ignore provided contents for most (all?) of the calls at this moment, we just serve the needed key + URL.
# TODO: Add missing ones. See https://github.com/svanheulen/mhff/wiki/MHX-DLC-Key-Negotiation for protocol references.

def make_login_v1_response(key, system_dir='', game_dir='', server_url=BASE_SERVER_URL):
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


# 3G JAP.

@app.route('/SSL/3ds/mh3g/login.cgi', methods=['POST'])
def login_mh3g():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh3g/')


# 3U EUR.

@app.route('/SSL/3ds/mh3gu_eu/login.cgi', methods=['POST'])
def login_mh3gu_eu():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh3gu_eu/')


@app.route('/SSL/wiiu/mh3ghd_eu/login.cgi', methods=['POST'])
def login_mh3ghd_eu():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_WIIU, '/mh3ghd_eu/')


# 3U USA.

@app.route('/SSL/3ds/mh3gu_us/login.cgi', methods=['POST'])
def login_mh3gu_us():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh3gu_us/')


@app.route('/SSL/wiiu/mh3ghd_us/login.cgi', methods=['POST'])
def login_mh3ghd_us():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_WIIU, '/mh3ghd_us/')


# 3U KOR.

@app.route('/SSL/3ds/mh3gu_kor/login.cgi', methods=['POST'])
def login_mh3gu_kor():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh3gu_kor/')


# ----------------------------------------------------------------------------------------------------------------------
# 4 JAP.

@app.route('/SSL/3ds/mh4/login.cgi', methods=['POST'])
def login_mh4():
    # Original server is not sending the URL for MH4 JP.
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, server_url='')


# 4 KOR.

@app.route('/SSL/3ds/mh4_kor/login.cgi', methods=['POST'])
def login_mh4_kor():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh4_kor/')


# 4 TWN.

@app.route('/SSL/3ds/mh4_tw/login.cgi', methods=['POST'])
def login_mh4_tw():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh4_tw/')


# ----------------------------------------------------------------------------------------------------------------------
# 4G JAP.

@app.route('/SSL/3ds/mh4g_nihon/login.cgi', methods=['POST'])
def login_mh4g_nihon():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_2, DIR_3DS, '/mh4g_nihon/')


# 4U EUR.

@app.route('/SSL/3ds/mh4g_eu_/login.cgi', methods=['POST'])
def login_mh4g_eu_():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_2, DIR_3DS, '/mh4g_eu_/')


# 4U USA.

@app.route('/SSL/3ds/mh4g_us_/login.cgi', methods=['POST'])
def login_mh4g_us_():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_2, DIR_3DS, '/mh4g_us_/')


# 4G KOR.

@app.route('/SSL/3ds/mh4g_kr_/login.cgi', methods=['POST'])
def login_mh4g_kr_():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_2, DIR_3DS, '/mh4g_kr_/')


# 4G TWN. This is a special case. Apparently this URL was used in the first versions of the taiwanese version for MH4G
# but was later changed in an update to simply use the JPN one. Adding support for it anyway.

@app.route('/SSL/3ds/redgiant/dl/pro_tw/login.cgi', methods=['POST'])
def login_mh4g_tw():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/redgiant/dl/pro_tw/')


if __name__ == '__main__':
    app.run()
