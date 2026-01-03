from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from flask import Flask, request, jsonify
import requests
import random
import uid_generator_pb2
from AccountPersonalShow_pb2 import AccountPersonalShowInfo
from secret import key, iv
import my_pb2
import output_pb2
import data_pb2
import hardest_pb2
import jwt_generator_pb2
import login_pb2
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import message_pb2
import my_message_pb2
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)

def hex_to_unwieldy(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(akiru_, aditya):
    message = uid_generator_pb2.uid_generator()
    message.akiru_ = akiru_
    message.aditya = aditya
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = AccountPersonalShowInfo()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def get_credentials(region):
    region = region.upper()
    if region == "IND":
        return "4262189763", "WIND-KDPTBHFCE-X"
    elif region in ["NA", "BR", "SAC", "US"]:
        return "4223240696", "WIND-Z28GSRBQQ-X"
    else:
        return "4222936602", "WIND-DXRGVOAWE-X"

def get_token(password, uid):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10)
        if res.status_code != 200:
            return None
        token_json = res.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        else:
            return None
    except Exception:
        return None

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            response_dict[k.strip()] = v.strip().strip('"')
    return response_dict

def get_jwt_token(region):
    auth_uid, auth_password = get_credentials(region)
    token_data = get_token(auth_password, auth_uid)
    if not token_data:
        return None

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno 640"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4

    try:
        encrypted = encrypt_message(AES_KEY, AES_IV, game_data.SerializeToString())
        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0",
            "Content-Type": "application/octet-stream"
        }
        r = requests.post(url, data=encrypted, headers=headers, verify=False)
        if r.status_code != 200:
            return None

        major = MajorLoginRes_pb2.MajorLoginRes()
        major.ParseFromString(r.content)
        return {
            "token": token_data["access_token"],
            "serverUrl": major.server_url
        }
    except Exception:
        return None

@app.route('/player-info', methods=['GET'])
def main():
    uid = request.args.get('uid')
    region = request.args.get('region')

    if not uid or not region:
        return jsonify({"error": "Missing uid or region"}), 400

    try:
        saturn_ = int(uid)
    except:
        return jsonify({"error": "Invalid UID"}), 400

    jwt_info = get_jwt_token(region)
    if not jwt_info:
        return jsonify({"error": "JWT failed"}), 500

    protobuf_data = create_protobuf(saturn_, 1)
    hex_data = protobuf_to_hex(protobuf_data)
    encrypted_hex = encrypt_aes(hex_data, key, iv)

    try:
        r = requests.post(
            f"{jwt_info['serverUrl']}/GetPlayerPersonalShow",
            headers={"Authorization": f"Bearer {jwt_info['token']}"},
            data=bytes.fromhex(encrypted_hex),
            verify=False
        )
        r.raise_for_status()
    except:
        return jsonify({"error": "Game server error"}), 502

    account_info = decode_hex(r.content.hex())

    result = {}
    if account_info.HasField("basic_info"):
        result["basicInfo"] = {
            "accountId": str(account_info.basic_info.account_id),
            "nickname": account_info.basic_info.nickname,
            "level": account_info.basic_info.level
        }

    result["credit"] = "@lakshitpatidar"
    return jsonify(result)
