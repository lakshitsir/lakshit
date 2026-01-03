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
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
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
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }

        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                
                # Also parse with MajorLoginRes_pb2
                major_login_res = MajorLoginRes_pb2.MajorLoginRes()
                try:
                    major_login_res.ParseFromString(response.content)
                    # Add additional response data
                    response_dict['account_id'] = major_login_res.account_id
                    response_dict['server_url'] = major_login_res.server_url
                    response_dict['ttl'] = major_login_res.ttl
                except:
                    pass
                
                return {
                    "token": response_dict.get("token", token_data.get("access_token", "")),
                    "serverUrl": response_dict.get("server_url", "")
                }
            except Exception as e:
                return None
        else:
            return None
    except Exception as e:
        return None

@app.route('/player-info', methods=['GET'])
def main():
    uid = request.args.get('uid')
    region = request.args.get('region')

    if not uid or not region:
        return jsonify({"error": "Missing 'uid' or 'region' query parameter"}), 400

    try:
        saturn_ = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID"}), 400

    jwt_info = get_jwt_token(region)
    if not jwt_info or 'token' not in jwt_info or not jwt_info['serverUrl']:
        return jsonify({"error": "Failed to fetch JWT token"}), 500

    api = jwt_info['serverUrl']
    token = jwt_info['token']

    protobuf_data = create_protobuf(saturn_, 1)
    hex_data = protobuf_to_hex(protobuf_data)
    encrypted_hex = encrypt_aes(hex_data, key, iv)

    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB51',
        'Content-Type': 'application/octet-stream',
    }

    try:
        response = requests.post(f"{api}/GetPlayerPersonalShow", headers=headers, data=bytes.fromhex(encrypted_hex), verify=False)
        response.raise_for_status()
    except requests.RequestException:
        return jsonify({"error": "Failed to contact game server"}), 502

    hex_response = response.content.hex()

    try:
        account_info = decode_hex(hex_response)
    except Exception as e:
        return jsonify({"error": f"Failed to parse Protobuf: {str(e)}"}), 500

    # Extract username dynamically
    username = "Unknown"

    if account_info.HasField("basic_info"):
        username = account_info.basic_info.nickname  # Fetch username from basic_info.nickname

    result = {}

    # Basic Info
    if account_info.HasField("basic_info"):
        basic_info = account_info.basic_info
        result["basicInfo"] = {
            "accountId": str(basic_info.account_id),
            "accountType": basic_info.account_type,
            "nickname": basic_info.nickname,
            "region": basic_info.region,
            "level": basic_info.level,
            "exp": basic_info.exp,
            "bannerId": basic_info.banner_id,
            "headPic": basic_info.head_pic,
            "rank": basic_info.rank,
            "rankingPoints": basic_info.ranking_points,
            "role": basic_info.role,
            "hasElitePass": basic_info.has_elite_pass,
            "badgeCnt": basic_info.badge_cnt,
            "badgeId": basic_info.badge_id,
            "seasonId": basic_info.season_id,
            "liked": basic_info.liked,
            "lastLoginAt": str(basic_info.last_login_at),
            "csRank": basic_info.cs_rank,
            "csRankingPoints": basic_info.cs_ranking_points,
            "weaponSkinShows": list(basic_info.weapon_skin_shows),
            "maxRank": basic_info.max_rank,
            "csMaxRank": basic_info.cs_max_rank,
            "accountPrefers": {},
            "createAt": str(basic_info.create_at),
            "title": basic_info.title,
            "externalIconInfo": {
                "status": "ExternalIconStatus_NOT_IN_USE",
                "showType": "ExternalIconShowType_FRIEND"
            },
            "releaseVersion": basic_info.release_version,
            "showBrRank": basic_info.show_br_rank,
            "showCsRank": basic_info.show_cs_rank,
            "socialHighLightsWithBasicInfo": {}
        }

    # Profile Info
    if account_info.HasField("profile_info"):
        profile_info = account_info.profile_info
        result["profileInfo"] = {
            "avatarId": profile_info.avatar_id,
            "skinColor": profile_info.skin_color,
            "clothes": list(profile_info.clothes),
            "equipedSkills": list(profile_info.equiped_skills),
            "isSelected": profile_info.is_selected,
            "isSelectedAwaken": profile_info.is_selected_awaken
        }

    # Clan Basic Info
    if account_info.HasField("clan_basic_info"):
        clan_info = account_info.clan_basic_info
        result["clanBasicInfo"] = {
            "clanId": str(clan_info.clan_id),
            "clanName": clan_info.clan_name,
            "captainId": str(clan_info.captain_id),
            "clanLevel": clan_info.clan_level,
            "capacity": clan_info.capacity,
            "memberNum": clan_info.member_num
        }

    # Captain Basic Info
    if account_info.HasField("captain_basic_info"):
        captain_info = account_info.captain_basic_info
        result["captainBasicInfo"] = {
            "accountId": str(captain_info.account_id),
            "accountType": captain_info.account_type,
            "nickname": captain_info.nickname,
            "region": captain_info.region,
            "level": captain_info.level,
            "exp": captain_info.exp,
            "bannerId": captain_info.banner_id,
            "headPic": captain_info.head_pic,
            "rank": captain_info.rank,
            "rankingPoints": captain_info.ranking_points,
            "role": captain_info.role,
            "hasElitePass": captain_info.has_elite_pass,
            "badgeCnt": captain_info.badge_cnt,
            "badgeId": captain_info.badge_id,
            "seasonId": captain_info.season_id,
            "liked": captain_info.liked,
            "lastLoginAt": str(captain_info.last_login_at),
            "csRank": captain_info.cs_rank,
            "csRankingPoints": captain_info.cs_ranking_points,
            "weaponSkinShows": list(captain_info.weapon_skin_shows),
            "maxRank": captain_info.max_rank,
            "csMaxRank": captain_info.cs_max_rank,
            "accountPrefers": {},
            "createAt": str(captain_info.create_at),
            "title": captain_info.title,
            "externalIconInfo": {
                "status": "ExternalIconStatus_NOT_IN_USE",
                "showType": "ExternalIconShowType_FRIEND"
            },
            "releaseVersion": captain_info.release_version,
            "showBrRank": captain_info.show_br_rank,
            "showCsRank": captain_info.show_cs_rank,
            "socialHighLightsWithBasicInfo": {}
        }

    # Pet Info
    if account_info.HasField("pet_info"):
        pet_info = account_info.pet_info
        result["petInfo"] = {
            "id": pet_info.id,
            "name": pet_info.name,
            "level": pet_info.level,
            "exp": pet_info.exp,
            "isSelected": pet_info.is_selected,
            "skinId": pet_info.skin_id,
            "selectedSkillId": pet_info.selected_skill_id
        }

    # Social Info
    if account_info.HasField("social_info"):
        social_info = account_info.social_info
        result["socialInfo"] = {
            "accountId": str(social_info.account_id),
            "language": "Language_EN",  # Map from social_info.language
            "modePrefer": "ModePrefer_BR",  # Map from social_info.mode_prefer
            "signature": social_info.signature,
            "rankShow": "RankShow_CS"  # Map from social_info.rank_show
        }

    # Diamond Cost Res
    if account_info.HasField("diamond_cost_res"):
        diamond_cost = account_info.diamond_cost_res
        result["diamondCostRes"] = {
            "diamondCost": diamond_cost.diamond_cost
        }

    # Credit Score Info
    if account_info.HasField("credit_score_info"):
        credit_info = account_info.credit_score_info
        result["creditScoreInfo"] = {
            "creditScore": credit_info.credit_score,
            "rewardState": "REWARD_STATE_UNCLAIMED",  # Map from credit_info.reward_state
            "periodicSummaryEndTime": str(credit_info.periodic_summary_end_time)
        }

    result['credit'] = '@Ujjaiwal'
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)#