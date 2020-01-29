# -*- coding:utf-8 -*-

import sys
sys.path.append('../')

from common.Console import console,debug
from common.RunCommand import runCommand
from common.EvilAnalyze import collect_ip_information

class NetWorkInfo():

    def __init__(self,config_content):
        self.config_content = config_content

        self.network_link = self.check_network_link()
        self.network_promisc = self.check_network_promisc()


    def check_network_link(self):
        ''' 查看网络链接状态 '''
        message = {}
        message['data'] = {}

        command = "netstat -antp 2> /dev/null | grep 'ESTABLISHED \| SYN_SENT \|SYN_RECEIVED' | awk '{print $1,$5,$7}'"
        content = runCommand(command).decode('utf-8').splitlines()
        if content:
            message['status'] = 1
            ID = 1
            for line in content:
                LinkMethod = line.split(' ')[0]
                IP,Port = line.split(' ')[1].replace("\n", "").split(':')
                PID = line.split(' ')[2].split('/')[0]
                IP_Information = collect_ip_information(IP)

                message['data'][str(ID)] = {}
                message['data'][str(ID)]['LinkMethod'] = LinkMethod
                message['data'][str(ID)]['IP'] = IP
                message['data'][str(ID)]['Port'] = Port
                message['data'][str(ID)]['IP_Information'] = IP_Information
                message['data'][str(ID)]['PID'] = PID

                ID += 1
        else:
            message['status'] = 0
        return message

    def check_network_promisc(self):
        message = {}

        command = "ifconfig 2>/dev/null| grep PROMISC | grep RUNNING"
        content = runCommand(command).decode('utf-8').splitlines()
        if len(content) > 0:
            message['status'] = 1
        else:
            message['status'] = 0
        return message

def run(config_content):
    information = NetWorkInfo(config_content)

    console(4)
    console(0,"开始网络分析：")

    console(0,"开始网络链接检测")
    if information.network_link['status'] == 0:
        console(1,"未发现建立远程通信的链接")
    else:
        for key,value in information.network_link['data'].items():
            if value['IP_Information']['status'] == 1:
                if value['IP_Information']['Overseas'] == 1:
                    console(3,f"紧急！！！发现境外远程通信链接 链接方式为 {value['LinkMethod']} IP和端口为 {value['IP']}:{value['Port']} 进程PID为 {value['PID']} 详细IP信息为 国家 {value['IP_Information']['Country']} 城市 {value['IP_Information']['City']} 所属运营商 {value['IP_Information']['ISP']}")
                else:
                    console(3,f"发现远程通信链接 链接方式为 {value['LinkMethod']} IP和端口为 {value['IP']}:{value['Port']} 进程PID为 {value['PID']} 详细IP信息为 国家 {value['IP_Information']['Country']} 城市 {value['IP_Information']['City']} 所属运营商 {value['IP_Information']['ISP']}")
            else:
                console(3,f"发现远程通信链接 链接方式为 {value['LinkMethod']} IP和端口为 {value['IP']}:{value['Port']} 进程PID为 {value['PID']}")

    console(0,"开始网卡是否开启混杂模式检测")
    if information.network_promisc['status'] == 1:
        console(2,"检测到网卡开启混杂模式")
    else:
        console(1,"网卡未开启混杂模式")
    console(4)

    del information