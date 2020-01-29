# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import os

from common.Console import console,debug
from common.StringCommon import analysis_string

class CommandHistoryInfo():

    def __init__(self,config_content):
        self.config_content = config_content
        self.files = self.config_content['files']
        self.directory = self.config_content['user_directory']

        self.history_status = self.check_history_status()

    def check_history_status(self):
        message = {}
        message['evil_content'] = []

        check_path = [self.files,self.directory]
        for path in check_path:
            if not os.path.exists(path):
                continue
            # 如果是目录就获取所有.bash_history文件
            if os.path.isdir(path):
                for user_home in os.listdir(path):
                    file = os.path.join('%s%s%s' % (path, user_home, '/.bash_history'))
                    if not os.path.exists(file):
                        continue
                    with open(file,'r',encoding="utf-8") as f:
                        for line in f:
                            content = analysis_string(line)
                            if content:
                                message['evil_content'].append(file + ". 内容为 : " + line)
                            else:
                                continue
            # 文件类操作
            else:
                with open(path,'r',encoding="utf-8") as f:
                    for line in f:
                        content = analysis_string(line)
                        if content:
                            message['evil_content'].append(path + ". 内容为 : " + line)
                        else:
                            continue

        return message



def run(config_content):
    information = CommandHistoryInfo(config_content)

    console(4)
    console(0,"开始历史命令安全检查")
    if len(information.history_status['evil_content']) == 0:
        console(1,"命令历史正常")
    else:
        for content in information.history_status['evil_content']:
            content = content.replace('\n','')
            console(3,f"存在恶意命令：{content}")

    console(4)

    del information