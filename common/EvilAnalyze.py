# -*- coding:utf-8 -*-

import re
import requests
import json

from common.Console import debug

http_ip_regex = r'(htt|ft)p(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ip_regex = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
local_ip = r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})'

def check_shell(content):
    try: 
        # 反弹Shell特征
        if (('bash' in content) and (('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (
                ('exec ' in content) and ('socket' in content)) or ('curl ' in content) or ('wget ' in content) or (
                'lynx ' in content) or ('bash -i' in content))) or (
                ".decode('base64')" in content) or ("exec(base64.b64decode" in content):
            return True
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return True
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return True
        # 下载执行特征
        elif (('wget ' in content) or ('curl ' in content)) and (
                (' -O ' in content) or (' -s ' in content)) and (
                ' http' in content) and (
                ('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or (
                'bash ' in content)) or (
                'socket' in content) and ('sh' in content):
                return True
        else:
            return False
    except:
        return False


def check_ip(content):
    if not re.search(ip_regex,content):
        return False
    if re.search(local_ip,content):
        return False
    return True


def collect_ip_information(ip):
    '''  
    返回数据格式
    {
        'status': [0|1],  # IP是否正常
        'Overseas'： [0|1], # 是否是境外IP
        'Country': str, # 所属国家 
        'City': str, # 所属城市
        'ISP': str # IP类型
    }
    '''
    message = {}

    try:
        URL = f'http://ip.taobao.com/service/getIpInfo.php?ip={ip}'
        res = requests.get(URL,timeout=5)
        data = res.json()
        if data['code'] == 0:
            country = data['data']['country']
            keyword=['中国','局域网','共享地址','本机地址','本地链路','保留地址','XX']
            if not country in keyword:
                message['Overseas'] = 1
            else:
                message['Overseas'] = 0
            message['status'] = 1
            message['Country'] = data['data']['country']
            message['City'] = data['data']['city']
            message['ISP'] = data['data']['isp']
        else:
            message['status'] = 0
        return message
    except requests.RequestException as e:
        message['status'] = 0
        return message
    except json.decoder.JSONDecodeError as e:
        message['status'] = 0
        return message