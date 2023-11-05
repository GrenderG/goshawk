from flask import Flask, send_from_directory, make_response, request
import ssl
import base64
import time
import datetime
import io
import hashlib
import hmac
import struct
from Crypto.Cipher import AES

# Constants.

BASE_SERVER_URL = 'http://goshawk.capcom.co.jp/'
X_SERVER_URL = 'http://spector.capcom.co.jp/'
XX_SERVER_URL = 'http://meteor.capcom.co.jp/'
SS_SERVER_URL = 'http://voodoo.capcom.co.jp/'

DIR_WIIU = 'wiiu'
DIR_3DS = '3ds'
DIR_P01 = 'p01'

BLOWFISH_KEY_TYPE_1 = 'Capcom123 '
BLOWFISH_KEY_TYPE_2 = 'AgK2DYheaOjyHGP8'

MHX_JP_KEY = b'Du9mgSyBmA7aQ5SX'
MHX_US_KEY = b'N3uExdqeA6r8jusbnN7mBRVWS8qe9sDaLe6viEVG'
MHX_EU_KEY = b'Xx9WzvFbJ5j3UxM6s2Q4bwYcG3vSmpX7H5eNuWQy'
MHX_TW_KEY= b'b4EeLZMUGw2N9Bun'
MHX_PUB_KEY = bytes.fromhex('30820122300d06092a864886f70d01010105000382010f003082010a0282010100b1303b6e08f1a1a294c67ff583e43410f326d7a3d8ce99ce8136fa9a7d3d93b3f9b12b861141dd24d2b8533fa21902d087390ce95c6eac47458627a18c50665e6f12239d855f5aa4a70212cdffaea809bab0d6fb5e33723c50c378edf690adf3e464906241226eadeff7ea60c83d83e4da43cf6269bc95c7c5635728b3af691d80e988bc1a04e6827a81b176a9e648c83f143b3eae56209ed34c6a69e4753bb9d79a931978e15bf72cc8a330e09fdd0613a5c3dcfb502a12857f3cc438f06a54f29041428a04f096b10bf05b5444e4d093e6b4ba0b3e506eb210181501c92e3d855aec4eb5556d29b0ffaa1264ef94e4df9b22ee379a910152ddff269bbd08270203010001')


MHXX_JP_KEY = b'5FtVyACe2sRus5Zga4QC3BxQ'
MHXX_TW_KEY = b'fQ5DN8yGN6ptcd5Kn8VsD2ud'
MHXX_PUB_KEY = bytes.fromhex('30820122300d06092a864886f70d01010105000382010f003082010a0282010100df2af97e99cd234b1b0b8a9220b64617d49886175ccba70925077d3b45bac1c06072e553105bd2314bc73a02701d2885cf9e465943f17865e7f6519b3050e2e728de215004d262bf2ed254e89e600dad990ced0b6324de8eb2f0c3a51df4df54f2123404234337d3f1b847d941812b436da03c7805ef5f8967c65832c91dbef03143205d13f99fd58188d54c60248c1b84fb47df0bb3e9a43af644859a6333bbeab9a4d69aab051a95511ad8dae2b2630a3c789697951345d7906dc60f96d116060d907b6df3078f2bbfe8d22e0c83aa5201bf8d62f9d840a17f69fab6393d81ad98d1218c70c6186f0c34adda21dffa678f0deb6c9d5b968a1e82188f07b9190203010001')


MHST_JP_KEY = b'ZwwnFCiJ78FUH9XWJdU6iaKH'
MHST_US_KEY = b'dE8h2BKWhG67NwDdrP74kSpN'
MHST_EU_KEY = b'dE8h2BKWhG67NwDdrP74kSpN'
MHST_TW_KEY = b'XEn37WdRAUJitYvCimd3Pzkq'
MHST_PUB_KEY = bytes.fromhex('30820122300d06092a864886f70d01010105000382010f003082010a0282010100c8c423b52a55fd2db99bdd9aa1ad9ac213c6f85ad0d85bc00712a0ebf8ea0e20739314db7e39dc9416331a20b60b429f4b63a1d6e33673d1d9dba8ec51cabff9a8248ffc9f41a4294243faa9e9bef850d5ca9f0cec7ac6016f8753f0bb9a579e97416eeab2275406a65e74b705f784c51eb0c04d96b8e1062b7ed995e9bffee675e8bba1c909a710540134a98a1c8df56da9bfee8ba21ae60404a6cb6b13c492619e6e9b80dc9af9fac7378dd30fed534846e03cd24e71b4a69a9d9c281dbb5cbe8b1119237b6eb960003f09c0fa632f05429bb2d190751d61d17f493edf316b71bbfcdd870e604e2ac02a64d6f780d08a4d0e8f58fa465a2d42bca160d2868d0203010001')

app = Flask(__name__)

# ----------------------------------------------------------------------------------------------------------------------
#helper function
#from https://github.com/kinnay/NintendoClients
def b64decode(text):
	text = text.replace(".", "+").replace("-", "/").replace("*", "=")
	return base64.b64decode(text)

def b64encode(text):
	# Convert to bytes if necessary
	if isinstance(text, str):
		text = text.encode()
	text = base64.b64encode(text).decode()
	return text.replace("+", ".").replace("/", "-").replace("=", "*")

def dictToQuery(d):
  query = ''
  idx = 0
  for key in d.keys():
    if idx != 0:
        query += '&'
    query += str(key) + '=' + str(d[key])
    idx +=1
  return query

# ----------------------------------------------------------------------------------------------------------------------
# DLC file routes.

@app.route(f'/{DIR_WIIU}/<path:path>', methods=['GET'])
def serve_wiiu_dlc_file(path):
    return send_from_directory(DIR_WIIU, path, mimetype='Content-Type: text/plain; charset=Shift_JIS')


@app.route(f'/{DIR_3DS}/<path:path>', methods=['GET'])
def serve_3ds_dlc_file(path):
    return send_from_directory(DIR_3DS, path, mimetype='Content-Type: text/plain; charset=Shift_JIS')

@app.route(f'/p01/<path:path>', methods=['GET'])
def serve_airu_dlc_file(path):
    return send_from_directory(DIR_P01, path)

# ----------------------------------------------------------------------------------------------------------------------
# Login CGI routes v1.
# Note: We ignore provided contents for most (all?) of the calls at this moment, we just serve the needed key + URL.

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


@app.route('/SSL/wiiu/mh3gu_eu/login.cgi', methods=['POST'])
def login_mh3ghd_eu():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_WIIU, '/mh3ghd_eu/')


# 3U USA.

@app.route('/SSL/3ds/mh3gu_us/login.cgi', methods=['POST'])
def login_mh3gu_us():
    return make_login_v1_response(BLOWFISH_KEY_TYPE_1, DIR_3DS, '/mh3gu_us/')


@app.route('/SSL/wiiu/mh3gu_us/login.cgi', methods=['POST'])
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


# Login CGI routes v3.
#See https://github.com/svanheulen/mhff/wiki/MHX-DLC-Key-Negotiation for protocol references.
def make_login_v3_response(key, rsa_pub_key, server_url, system_dir='', game_dir=''): 
   try:
    #req
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
    bstream = io.BytesIO(data)
    protocol_version= int.from_bytes(bstream.read(1), "big")
    service_locator_len=  int.from_bytes(bstream.read(1), "big")
    service_locator= bstream.read(service_locator_len).decode()
    unk1= int.from_bytes(bstream.read(4), "big")
    unk2= int.from_bytes(bstream.read(4), "big")
    unk3= int.from_bytes(bstream.read(4), "big")
    unk4= int.from_bytes(bstream.read(2), "big")
    unk5 = None
    if protocol_version == 3:
     unk5= int.from_bytes(bstream.read(1), "big")
    else:
     unk5= int.from_bytes(bstream.read(2), "big")
    client_nonce = bstream.read(4)
    client_hmac = bstream.read(32)
    #
    #Decode the service_locator token and get the userid. In the current implementation, only userid is contained.
    userid = int(b64decode(service_locator))
    uid = struct.pack('>I', userid)

    #Verification client hmac
    '''
    client_hmac_key  = hashlib.sha256(uid + client_nonce).digest()
    h = hmac.new( client_hmac_key, data[:-32], hashlib.sha256 )
    if(h.hexdigest() != client_hmac):
        print('error! client hmac is not same')
    '''
    
    #resp
    # - short bkey_len;
    # - char encrypted_blowfish_key[bkey_len];
    # - short rkey_len;
    # - char rsa_pubkey[rkey_len];
    # - short url_len;
    # - char dlc_url[url_len];
    # - int server_nonce;
    # - char server_hmac[32];
       
    server_nonce = int(time.time()) 
    server_nonce_bytes = server_nonce.to_bytes(4, 'big')
    
    aeskey = uid + client_nonce + server_nonce_bytes + uid
    iv = 16 * b'\0'
    aes = AES.new(aeskey, AES.MODE_CBC, iv)
    bkey = aes.encrypt(key)
    bkey_len = len(bkey).to_bytes(2, 'big')
    rkey_len = len(rsa_pub_key).to_bytes(2, 'big')
    url_bytes = server_url.encode('shift_jis') + system_dir.encode('shift_jis') + game_dir.encode('shift_jis')
    url_len = len(url_bytes).to_bytes(2, 'big')
    client_hmac_key  = hashlib.sha256(uid + client_nonce + server_nonce_bytes).digest()
    response_bytes = bkey_len + bkey + rkey_len + rsa_pub_key + url_len + url_bytes + server_nonce_bytes
    hs= hmac.new( client_hmac_key, response_bytes, hashlib.sha256 )
    server_hmac = hs.digest()
    response_bytes += server_hmac
    response = make_response(response_bytes)
    # Remove Content-Type header since original servers are not sending it.
    response.headers.remove('Content-Type')
    return response
   except Exception as e:
    print(e)
    response = make_response('')
    response.headers.remove('Content-Type')
    return response
    
#MHX JP
@app.route('/SSL/3ds/mhx/login_new_jp.cgi', methods=['POST'])
def login_mhx_jp():
    #add extra padding
    return make_login_v3_response(MHX_JP_KEY + b"\x10" * 0x10, MHX_PUB_KEY, X_SERVER_URL, DIR_3DS, '/mhx_new_jp/')

#MHX US
@app.route('/SSL/3ds/mhx/login_us.cgi', methods=['POST'])
def login_mhx_us():
    #add extra padding
    return make_login_v3_response(MHX_US_KEY + b"\x08" * 0x08, MHX_PUB_KEY, X_SERVER_URL, DIR_3DS, '/mhx_us/')

#MHX EU
@app.route('/SSL/3ds/mhx/login_eu.cgi', methods=['POST'])
def login_mhx_eu():
    #add extra padding
    return make_login_v3_response(MHX_EU_KEY + b"\x08" * 0x08, MHX_PUB_KEY, X_SERVER_URL, DIR_3DS, '/mhx_eu/')

#MHX TW
@app.route('/SSL/3ds/mhx/login_new_tw.cgi', methods=['POST'])
def login_mhx_tw():
    #add extra padding
    return make_login_v3_response(MHXX_JP_KEY + b"\x10" * 0x10, MHX_PUB_KEY, X_SERVER_URL, DIR_3DS, '/mhx_new_tw/')

#MHXX JP
@app.route('/SSL/3ds/mhxx/login_jp.cgi', methods=['POST'])
def login_mhxx_jp():
    #add extra padding
    return make_login_v3_response(MHXX_JP_KEY + b"\x08" * 0x8, MHXX_PUB_KEY, XX_SERVER_URL, DIR_3DS, '/mhxx_jp/')

#MHXX TW
@app.route('/SSL/3ds/mhxx/login_tw.cgi', methods=['POST'])
def login_mhxx_tw():
    #add extra padding
    return make_login_v3_response(MHXX_TW_KEY + b"\x08" * 0x8, MHXX_PUB_KEY, XX_SERVER_URL, DIR_3DS, '/mhxx_tw/')

 
#MHST JP
@app.route('/SSL/3ds/mhss/login.cgi', methods=['POST'])
def login_mhst_jp():
    #add extra padding
    return make_login_v3_response(MHST_JP_KEY + b"\x08" * 0x08, MHST_PUB_KEY, SS_SERVER_URL, DIR_3DS, '/mhss_jp/')

#MHST US
@app.route('/SSL/3ds/mhss/login_us.cgi', methods=['POST'])
def login_mhst_us():
    #add extra padding
    return make_login_v3_response(MHST_US_KEY + b"\x08" * 0x08, MHST_PUB_KEY, SS_SERVER_URL, DIR_3DS, '/mhss_us/')

#MHST EU
@app.route('/SSL/3ds/mhss/login_eu.cgi', methods=['POST'])
def login_mhst_eu():
    #add extra padding
    return make_login_v3_response(MHST_EU_KEY + b"\x08" * 0x08, MHST_PUB_KEY, SS_SERVER_URL, DIR_3DS, '/mhss_eu/')

#MHST TW
@app.route('/SSL/3ds/mhss/login_tw.cgi', methods=['POST'])
def login_mhst_tw():
    #add extra padding
    return make_login_v3_response(MHST_TW_KEY + b"\x08" * 0x08, MHST_PUB_KEY, SS_SERVER_URL, DIR_3DS, '/mhss_tw/')
 
 
# ----------------------------------------------------------------------------------------------------------------------
# 3ds NASC server
#https://nasc.nintendowifi.net/ac
def nasc_response():
    resp_dict ={}
    try:
        req = request.form.to_dict()
        action  = b64decode(req['action']).decode()
        print(action)
        if action =="LOGIN":
            titleid = b64decode(req['titleid']).decode()
            gameid = b64decode(req['gameid']).decode()
            resp_dict['locator'] = b64encode('0.0.0.0:0') #It varies depending on the gameid.
            resp_dict['retry'] = b64encode('0')
            resp_dict['returncd'] = b64encode('001')
            resp_dict['token'] = b64encode('notActualToken') #Temp value
            resp_dict['datetime'] = b64encode(str(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")))
        elif action =="SVCLOC":
            userid = b64decode(req['userid']).decode()
            resp_dict['retry'] = b64encode('0')
            resp_dict['returncd'] = b64encode('007')
            resp_dict['servicetoken'] = b64encode(userid) #Real server contains more information include userid and freind code and current time with encryption. We currently only need userid.
            resp_dict['statusdata'] = b64encode('Y')
            resp_dict['svchost'] = b64encode('n/a')
            resp_dict['datetime'] = b64encode(str(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")))
        else:
            raise ValueError('Unknown action.')
        resp = dictToQuery(resp_dict)
        response = make_response(resp)
        response.headers['Content-Type'] = 'text/plain;charset=ISO-8859-1'
        return response
    except Exception as e:
        resp_dict ={};
        resp_dict['retry'] = b64encode('1')
        resp_dict['returncd'] = b64encode('109')
        resp_dict['datetime'] = b64encode(str(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")))
        resp = dictToQuery(resp_dict)
        response = make_response(resp)
        response.headers['Content-Type'] = 'text/plain;charset=ISO-8859-1'
        return response
    
@app.route('/ac',methods=['POST'])
def nasc_ac():
    return nasc_response()


#http://conntest.nintendowifi.net/
@app.route('/', methods=['GET'])
def conn_test():
    response = send_from_directory("conntest", 'test.html')
    response.headers['X-Organization'] = 'Nintendo'
    response.headers['Content-type'] = 'text/html'
    return response

    
if __name__ == '__main__':
    app.run()
