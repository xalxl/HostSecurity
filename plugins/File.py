# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import time
import os

from common.ErrorException import FileErrorException
from common.Console import console
from common.RunCommand import runCommand
from common.FileCommon import get_current_directory_files,analysis_file

class FileInfo():

    def __init__(self,config_content):
        self.config_content = config_content

        # 检测被改动过的文件
        self.start_time = self.config_content['moved_file']['time'].split('~')[0]
        if len(config_content['moved_file']['time'].split('~')) != 2:
            localtime = time.localtime(time.time() - 180)
            self.end_time = time.strftime("%Y-%m-%d %H:%M:%S", localtime)
        else:
            self.end_time = self.config_content['moved_file']['time'].split('~')[1]
        self.directory_to_check = self.config_content['moved_file']['directory']
        self.moved_files = self.check_moved_files()

        # 检测文件hash值
        self.check_dir = self.config_content['command_status']['check_dir'].split(':')
        self.command_status = self.check_command_status()

        # 检测恶意文件
        self.binarry_files = self.config_content['system_integrity']['binarry_directory'].split(':')
        self.check_files = self.config_content['system_integrity']['check_files'].split(':')
        self.system_integrity = self.check_system_integrity()

        # 检测临时目录文件
        self.tmp_directory = self.config_content['tmp']['directory'].split(':')
        self.tmp_file_status = self.check_tmp_file_status()

        # 检测用户
        self.user_directory = self.config_content['user']['directory'].split(':')
        self.user_file_status = self.check_user_file_status()

        # 检查隐藏文件
        self.hidden_directory = self.config_content['hide']['directory']
        self.hide_files_status = self.check_hide_files_status()

    def check_moved_files(self):
        message = {}
        message['moved_files'] = []
        command = f"find {self.directory_to_check} -newermt '{self.start_time}' ! -newermt '{self.end_time}' 2>/dev/null"
        files = runCommand(command).strip().decode('utf-8').split()
        message['file_count'] = len(files)
        # 去除找到的目录
        for file in files:
            if os.path.isfile(file):
                message['moved_files'].append(file)
        return message


    def check_command_status(self):
        '''  
            检查系统命令是否存在被替换
            检测与历史命令Hash值是否一致
        '''
        message = {}
        message['safe_command'] = [] # 未改变
        message['unsafe_command'] = [] # 被改变
        message['unexist_command'] = [] # 不存在

        message['prelink_command'] = [] # prelink改变过的

        try:
            # 获取保存好的正确的文件哈希字典 
            right_files_hash_db = self.get_right_files_hash_db()
            # 检测是否存在prelink服务
            Prelink_Server,Prelink_Server_Log = self.check_prelink_server_status()

            for key,right_hash in right_files_hash_db.items():
                if not os.path.exists(key) and not os.path.isfile(key):
                    message['unexist_command'].append(key)
                    continue
                check_hash = self.get_hash(key)
                if check_hash != right_hash: 
                    if Prelink_Server and len(Prelink_Server_Log) > 0 and Prelink_Server_Log.find(key):
                        message['prelink_command'].append(key)
                    else:
                        message['unsafe_command'].append(key)
                else:
                    message['safe_command'].append(key)
            
        except FileErrorException as e:
            message['error_message'] = str(e)
        finally:
            return message


    def check_system_integrity(self):
        message = {}
        message['evil_file'] = []
        message['wrong_file'] = []

        for drt in self.binarry_files:
            if not os.path.exists(drt):
                continue
            for file in get_current_directory_files(drt):
                if os.path.basename(file) in self.check_files: # 只检测重要文件
                    content = analysis_file(file)
                    if content:
                        message['evil_file'].append(file + ". 内容为 : " + content)
                    else:
                        continue
                else:
                    continue
        return message


    def check_tmp_file_status(self):
        ''' 检测临时目录文件状态 '''
        message = {}
        message['evil_file'] = []
        message['wrong_file'] = []

        for drt in self.tmp_directory:
            if not os.path.exists(drt):
                continue
            for file in get_current_directory_files(drt):
                content = analysis_file(file)
                if content:
                    message['evil_file'].append(file + ". 内容为 : " + content)
                else:
                    continue
            else:
                continue
        return message

    def check_user_file_status(self):
        ''' 检测临时目录文件状态 '''
        message = {}
        message['evil_file'] = []
        message['wrong_file'] = []

        for drt in self.user_directory:
            if not os.path.exists(drt):
                continue
            for file in get_current_directory_files(drt):
                content = analysis_file(file)
                if content:
                    message['evil_file'].append(file + ". 内容为 : " + content)
                else:
                    continue
            else:
                continue
        return message

    def check_hide_files_status(self):
        '''  检测是否存在可疑隐藏文件 '''
        message = {}
        message['evil_file'] = []
        message['wrong_file'] = []

        command = f'find {self.hidden_directory} ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/private/*" -name ".*" 2>/dev/null'
        files = runCommand(command).decode('utf-8').splitlines()

        for file in files:
            if file == '/usr/share/man/man1/..1.gz':
                continue
            else:
                content = analysis_file(file)
                if content:
                    message['evil_file'].append(file + ". 内容为 : " + content)
                else:
                    continue
        return message


    def check_prelink_server_status(self):
        prelink_log_path = self.config_content['command_status']['prelink_log_path'].split(':')
        for path in prelink_log_path:
            if os.path.exists(path):
                try:
                    file = open(path,'r',encoding='utf-8')
                    file_content = file.read()
                finally:
                    file_content.close()
                return True,file_content
        return False,""


    def get_right_files_hash_db(self):
        '''  获取保存好的文件Hash值 '''
        command_hash_list = {}
        file = self.config_content['command_status']['hash_db']
        if not os.path.exists(file):
            raise FileErrorException('hash_db文件必须存在')
        if os.path.getsize(file) ==0:
            raise FileErrorException('hash_db文件不能为空')
        with open(file,'r',encoding='utf-8') as f:
            for line in f:
                if line != "" or line !=None:
                    command = line.split('||')[0]
                    command_hash = line.split('||')[1]
                    command_hash_list[command] = command_hash
        return command_hash_list

    def get_hash(self,file):
        ''' 获得给定文件的Hash值 '''
        import hashlib
        try:
            m = hashlib.md5()
            size = 102400
            f = open(file, 'rb')
            while True:
                content = f.read(size)
                if not content:
                    break
                m.update(content)
            f.close()
            return m.hexdigest()
        except:
            return "error"


def run(config_content):
    information = FileInfo(config_content)

    console(4)
    console(0,"开始文件安全检查")

    console(0,"指定时间内主机上所有增加或改动过的文件：")
    for file in information.moved_files['moved_files']:
        console(2,"此文件被添加或修改过：" + file)
    console(1,f"指定时间内一共 {information.moved_files['file_count']} 处文件被增加或改动")

    console(0,"检查系统重要可执行文件Hash值：")
    if 'error_message' in information.command_status.keys():
        console(3,"出现错误：" + information.command_status['error_message'])
    else:
        if len(information.command_status['unexist_command']) == 0 and len(information.command_status['unsafe_command']) == 0:
            console(1,"命令哈希值全部正常")
        else:
        # for command in information.command_status['safe_command']:
        #     console(1,f" {command} 命令正常")
            for command in information.command_status['prelink_command']:
                console(2,f" {command} 由prelink服务更新过 请手动检查")
            for command in information.command_status['unexist_command']:
                console(2,f" {command} 命令不存在 请手动修改配置文件")
            for command in information.command_status['unsafe_command']:
                console(3,f" {command} 命令哈希值不正确 可能存在被替换的风险 请手动排查或更新数据配置")
                

    console(0,"检查系统上可能存在的恶意文件：")
    if len(information.system_integrity['evil_file']) == 0:
        console(1,"未检测出关键文件存在恶意特征")
    else:
        for file in information.system_integrity['evil_file']:
            console(3,f"存在恶意文件：{file} . ")
        # for file in information.system_integrity['wrong_file']:
        #     console(2,f"文件查询出错：{file} . 可能文件无权限打开或文件为空或文件太大")

    console(0,"检查系统临时文件目录：")
    if len(information.tmp_file_status['evil_file']) == 0:
        console(1,"未检测出关键文件存在恶意特征")
    else:
        for file in information.tmp_file_status['evil_file']:
            console(3,f"存在恶意文件：{file} . ")
        # for file in information.tmp_file_status['wrong_file']:
        #     console(2,f"文件查询出错：{file} . 可能文件无权限打开或文件为空或文件太大")

    console(0,"检查系统各用户目录：")
    if len(information.user_file_status['evil_file']) == 0:
        console(1,"未检测出关键文件存在恶意特征")
    else:
        for file in information.user_file_status['evil_file']:
            console(3,f"存在恶意文件：{file} . ")
        # for file in information.user_file_status['wrong_file']:
        #     console(2,f"文件查询出错：{file} . 可能文件无权限打开或文件为空或文件太大")

    console(0,"检查系统可疑隐藏文件：")
    if len(information.hide_files_status['evil_file']) == 0:
        console(1,"未发现可疑隐藏文件")
    else:
        for file in information.hide_files_status['evil_file']:
            console(3,f"存在可疑隐藏文件：{file}")

    console(4)

    del information