# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import os

from common.Console import console,debug
from common.FileCommon import get_current_directory_files,analysis_file
from common.StringCommon import analysis_string
from common.RunCommand import runCommand

class BackdoorInfo:

    def __init__(self,config_content):
        self.config_content = config_content
        self.configfiles = config_content['configfiles'].split(':')
        self.homefiles = config_content['homefiles'].split(':')
        self.TAG = config_content['PATHBackdoor']['name'].split(':')
        self.cron_files = config_content['Cron']['files'].split(':')

        self.PATHBackdoor = self.check_PATHBackdoor()
        self.ld_so_preload = self.check_ld_so_preload()
        self.cron_status = self.check_cron_status()
        self.ssh_wrapper = self.check_ssh_wrapper()
        self.init_status = self.check_init_status()
        self.suid_stauts = self.check_suid_status()

    def check_conf(self,name,file):
        if not os.path.exists(file): return 
        if os.path.isdir(file): return

        with open(file) as f:
            for line in f:
                if len(line) < 3:continue
                if line[0] == '#': continue
                if 'export ' + name in line:
                    return line
        info = analysis_file(file)
        if info:
            return info
        return


    def check_tag(self,tag):
        message = {}
        message['status'] = 0
        message['data'] = {}
        ID = 1

        for directory in os.listdir('/home/'):
            for homefile in self.homefiles:
                file = os.path.join('%s%s%s' % ('/home/', directory, homefile))
                info = self.check_conf(tag,file)
                if info:
                    message['status'] = 1
                    message['data'][ID] = {'file' : file,'content' : info.replace("\n","")}
                    ID += 1
        for file in self.configfiles:
            if os.path.isdir(file):
                for f in get_current_directory_files(file):
                    info = self.check_conf(tag,f)
                    if info:
                        message['status'] = 1
                        message['data'][ID] = {'file' : f ,'content' : info.replace("\n","")}
                        ID += 1
            else:
                info = self.check_conf(tag,file)
                if info:
                    message['status'] = 1
                    message['data'][ID] = {'file' : file,'content' : info.replace("\n","")}
                    ID += 1  
        return message

    # 环境变量后门
    def check_PATHBackdoor(self):
        message = {}
        message['status'] = 0
        message['data'] = {}
        ID = 1
        for tag in self.TAG:
            info = self.check_tag(tag)
            if info['status'] == 1:
                message['status'] = 1
                message['data'][ID] = {'tag' : tag, 'content': info['data']}
                ID += 1
        return message

    # ld.so.preload后门检测
    def check_ld_so_preload(self):
        message = {}
        message['status'] = 0
        message['data'] = {}
        ID = 1

        if os.path.exists('/etc/ld.so.preload'):
            with open('/etc/ld.so.preload','r',encoding='utf-8') as f:
                for line in f:
                    if not len(line) > 3:continue
                    if line[0] == '#':continue
                    info = analysis_string(line)
                    if info:
                        message['status'] = 1
                        message['data'][ID] = {file:"/etc/ld.so.preload",'content':info}
                        ID += 1
        return message

    # crontab后门
    def check_cron_status(self):
        message = {}
        message['status'] = 0
        message['data'] = {}
        ID = 1

        for directory in self.cron_files:
            for file in get_current_directory_files(directory):
                with open(file,'r',encoding='utf-8') as f:
                    for line in f:
                        info = analysis_string(line)
                        if info:
                            message['status'] = 1
                            message['data'][ID] = {'file':file,'content':info}
                            ID += 1
        return message

    # SSH Wrapper后门
    def check_ssh_wrapper(self):
        message = {}
        message['status'] = 0

        command = "file /usr/sbin/sshd 2>/dev/null" 
        content = runCommand(command).decode('utf-8')
        if len(content):
            if ('ELF' not in content) and ('executable' not in content):
                message['status'] = 1

        return message

    # 开机启动项检查
    def check_init_status(self):
        message = {}
        message['status'] = 0 
        message['data'] = {}
        ID = 1
        init_path = self.config_content['Init']['files'].split(':')

        for path in init_path:
            if not os.path.exists(path): continue
            if os.path.isfile(path):
                content = analysis_file(path)
                if content:
                    message['status'] = 1
                    message['data'][ID] = {'file':path,'content':content}
                    ID += 1

            else:
                for file in get_current_directory_files(path):
                    content = analysis_file(file)
                    if content:
                        message['status'] = 1
                        message['data'][ID] = {'file':path,'content':content}
                        ID += 1

        return message

    # SUID提权检查
    def check_suid_status(self):
        message = {}
        message['status'] = 0 
        message['data'] = {}
        ID = 1

        directory = self.config_content['SUID']['directory']
        exclude_command = self.config_content['SUID']['exclude']

        command = f"find {directory} ! -path '/proc/*' -type f -perm -4000 2>/dev/null | grep -vE '{exclude_command}'"
        content = runCommand(command).decode('utf-8').splitlines()
        if content:
            message['status'] = 1
            for line in content:
                message['data'][ID] = {'content':line}
                ID+=1

        return message

def run(config_content):
    information = BackdoorInfo(config_content)

    console(4)
    console(0,"开始后门检测")
    console(0,"检测环境变量")
    if information.PATHBackdoor['status'] == 0:
        console(1,"未发现环境变量后门")
    else:
        for key_1,content in information.PATHBackdoor['data'].items():
            for key_2,value_2 in content.items():
                if type(value_2) == dict:
                    for key_3,value_3 in value_2.items():
                        console(3,f"发现环境变量后门 后门类型 {content['tag']} . 文件 {value_3['file']} . 内容 {value_3['content']} . 请人工检查")

    console(0,"开始检测ld.so.preload后门：")
    if information.ld_so_preload['status'] == 0:
        console(1,"未发现ld.so.preload后门")
    else:
        for key,value in information.ld_so_preload['data'].items():
            console(3,f"发现ld.so.preload后门 文件位置 {value['file']} . 内容 {value['content']}")

    console(0,"开始检测定时任务后门")
    if information.cron_status['status'] == 0:
        console(1,"未发现定时任务后门")
    else:
        for key,value in information.cron_status['data'].items():
            console(3,f"发现定时任务后门 文件位置 {value['file']} . 内容 {value['content']}")

    console(0,"开始检测SSH Server wrapper后门")
    if information.ssh_wrapper['status'] == 0:
        console(1,"未检测到SSH Server wrapper后门")
    else:
        console(3,"检测到SSH Server wrapper后门 。文件位于 /usr/sbin/sshd")
    
    console(0,"开始检测系统启动项")
    if information.init_status['status'] == 0:
        console(1,"未发现异常系统启动项")
    else:
        for key,value in information.init_status['data'].items():
            console(3,f"发现异常系统启动项 文件 {value['file']} . 内容 {value['content']} .")

    console(0,"开始检测SUID提权后门")
    if information.suid_stauts['status'] == 0:
        console(1,"未检测到SUID提权后门")
    else:
        for key,value in information.suid_stauts['data'].items():
            console(3,f"检测到SUID提权后门 内容为 {value['content']}")
    console(4)


    del information