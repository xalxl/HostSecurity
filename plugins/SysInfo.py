# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import platform
import socket

from common.Console import console,debug

# 系统信息
class sysinfo():

    def __init__(self,ssh=False):
        self.hostname = "" # 主机名
        self.sys_version = "" # 内核版本
        self.host_version = "" # 系统版本
        self.arch = "" # 系统架构
        self.remote_ip = "" # 公网IP

        self.get_info()

    # 获取系统相关信息
    def get_info(self):
        self.hostname = platform.node()
        self.sys_version = platform.uname()[2]
        self.host_version = platform.platform()
        self.arch = platform.machine()

        try:
            import requests
            res = requests.get('http://ifconfig.me/ip',timeout=5)
            self.remote_ip = res.content.decode('utf-8')
        except:
            self.remote_ip = "NETWORKERROR"


def run():
    information = sysinfo()
    console(4)
    console(0,"系统信息：")
    console(1,"主机名 : " + information.hostname)
    console(1,"内核版本 : " + information.sys_version)
    console(1,"系统版本 : " + information.host_version)
    console(1,"系统架构 : " + information.arch)

    if information.remote_ip == "NETWORKERROR":
        console(3,"公网IP： 未联网或网络不通畅，无法显示公网IP")
    else:
        console(1,"公网IP：" + information.remote_ip)

    console(4)

    del information
