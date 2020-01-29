# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import os

from common.Console import console,debug
from common.RunCommand import runCommand

class System():

    def __init__(self,config_content):
        self.config_content = config_content
        self.alias_status = self.check_alias_status()

    def check_alias_status(self):
        ''' 检查alias项是否存在异常 '''
        message = {}
        message['evil_alias'] = []
        message['error_message'] = []

        check_common_files = self.config_content['alias']['common_files'].split(':')
        check_user_files = self.config_content['alias']['user_files'].split(':')
        sensitive_command = self.config_content['alias']['alias_sensitive_commad'].split(',')

        for dir in os.listdir('/home/'): # 加入各个用户目录的.bashrc
            for item in check_user_files:
                check_common_files.append(os.path.join(f'/home/{dir}/{item}'))

        for file in check_common_files:
            if not os.path.exists(file):
                message['error_message'].append(f'路径不存在：{file}')
                continue
            try:
                with open(file,'r',encoding ='utf-8') as f:
                    for line in f:
                        if 'alias' in line:
                            for command in sensitive_command:
                                if 'alias ' + command + '=' in line:
                                    evil_alias_commad = Evil_Alias_Commad(file,line)
                                    message['evil_alias'].append(evil_alias_commad) 
            except:
                message['error_message'].append(f'无权限打开 {file} . 请检查权限情况')
        return message


class Evil_Alias_Commad():

    def __init__(self,belongfile,content):
        self.belongfile = belongfile
        self.content = content


def run(config_content):
    information = System(config_content)

    console(4)
    console(0,"开始系统初始化项检查")
    console(0,"开始检查系统Alias：")

    if len(information.alias_status['error_message']) != 0:
        for error_message in information.alias_status['error_message']:
            console(2,error_message)

    if len(information.alias_status['evil_alias']) != 0:
        for result in information.alias_status['evil_alias']:
            console(3,f"发现异常Alias  所属文件 : {result.belongfile}  .  命令为 : {result.content}")
    else:
        console(1,"未发现异常Alias")
    console(4)

    del information