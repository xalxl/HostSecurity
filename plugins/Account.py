# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import os

from common.Console import console,debug
from common.RunCommand import runCommand


class AccountInfo():

    def __init__(self,config_content):
        self.config_content = config_content
        self.special_accounts = self.check_special_account()
        self.password_policy = self.check_password_policy()
        self.current_user = self.check_current_user()
        self.TMOUT = self.check_TMOUT()
        self.sudo_status = self.check_sudo_status()
        self.authorized_keys_status = self.check_authorized_keys_status()
        self.passwd_file_status = self.check_passwd_file_status()
    
    def check_special_account(self):
        ''' 检查特殊账户，是否存在空密码账户和或者UID为0的非root账户 '''
        message = {}
        message['status'] = 1
        message['exception'] = ""
        message["passwdpath"] = self.config_content['special_counts']['passwdpath']
        message["shadowpath"] = self.config_content['special_counts']['shadowpath']
        message["evil_users"] = []
        message["empty_users"] = []

        #command = 'awk -F[:] \'{ if($3 == 0 && $1 != "root") print $1}\' '+ message["passwdpath"] # UID为0的账户
        #for evil_user in runCommand(command).strip().decode('utf-8').split('\n'): 
        #    message["evil_users"].append(evil_user) 

        f = open(message["passwdpath"],'r',encoding='utf-8')
        for line in f.readlines():
            if line.split(':')[0] != 'root' and int(line.split(':')[3]) == 0:
                user = line.split(':')[0]
                message["evil_users"].append(user)
        f.close()

        try:
            f = open(message["shadowpath"],'r',encoding="utf-8")
            for line in f.readlines():
                if len(line.split(':')[1]) == 0 :
                    empty_user = line.split(':')[0]
                    message["empty_users"].append(empty_user) 

            #command = "awk -F[:] 'length($2)==0 {print $1}' " + message["shadowpath"] + " > /dev/null 2>&1" # 空密码用户
            #result = runCommand(command).strip().decode('utf-8')
            #for empty_user in result.split('\n'): 
            #    message["empty_users"].append(empty_user) 
                    
        except:
            message['status'] = 0
            message['exception'] = "无权限读取 " + message["shadowpath"]  + " 的内容" 

        finally:
            f.close()
            return message

    def check_password_policy(self):
        ''' 查看账户策略限制 '''
        message = {}
        message['status'] = 1
        message['filepath'] = self.config_content['policy']['policyfilepath']
        
        if not os.path.exists(message['filepath']):
            message['status'] = 0
            return message

        message['pass_max'] = runCommand("cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'").strip().decode('utf-8') # 口令最大生存周期 
        message['pass_min'] = runCommand("cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}'").strip().decode('utf-8') # 口令最小生存周期
        message['pass_len'] = runCommand("cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'").strip().decode('utf-8') # 口令最小长度
        message['pass_age'] = runCommand("cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}'").strip().decode('utf-8') # 口令过期警告时间天数

        return message

    def check_TMOUT(self):
        ''' 检查是否设置账号主动注销 '''
        message = {}
        message['status'] = 1
        message['filepath'] = self.config_content['TMOUT']['file']
        
        if not os.path.exists(message['filepath']):
            message['status'] = 0
            return message

        message['TMOUT_Time'] = runCommand("cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'").strip().decode('utf-8') # 提取TMOUT设置的时间
        return message


    def check_current_user(self):
        ''' 检查当前登陆的用户 '''
        message = {}
        message['status'] = 0
        message['current_user'] = []

        command = "who"
        result = runCommand(command).strip().decode('utf-8')
        if result:
            message['status'] = 1

            userinfo = {}
            for info in resutl:
                current_user = info.split()[0]
                login_time = info.split()[2]+ " " +info.split()[3]
                userinfo['current_user'] = current_user
                userinfo['login_time'] = login_time

                remote_ip = info.split()[-1].replace('(','').replace(')','')
                if remote_ip == ":0":
                    userinfo['remote_ip'] = 'localhost'
                else:
                    userinfo['remote_ip'] = remote_ip
                message['current_user'].append(userinfo)
        return message


    def check_sudo_status(self):
        message = {}
        message['status'] = 0
        message['data'] = {}
        ID = 1
        files = self.config_content['SUDO']['files'].split(':')

        for file in files:
            command = f"cat {file} 2> /dev/null | grep -v '#' | grep '[ALL=(ALL)|ALL=(ALL:ALL)]' | "  + " awk '{print $1}'"
            content = runCommand(command).decode('utf-8').splitlines()
            for user in content:
                if user[0] != '%' and user.replace("\n", "") != 'root':
                    message['status'] = 1
                    message['data'][ID] = {'file':file,'content':'user'}
                    ID += 1
        return message

    # 公钥文件情况
    def check_authorized_keys_status(self):
        message = {}
        message['status'] = 0
        message['data'] = {}
        ID = 1

        directory = os.listdir('/home/')
        directory.append('root')
        for user in directory:
            if user == 'root':
                path = '/root/.ssh/authorized_keys'
            else:
                path =  os.path.join('%s%s%s' % ('/home/', user, '/.ssh/authorized_keys'))
            if os.path.exists(path):
                with open(path,'r',encoding='utf-8') as f:
                    for line in f:
                        agent = line.split()[2]
                        if len(agent):
                            message['status'] = 1
                            message['data'][ID] = {'file': path, 'content':agent}
                            ID += 1
        return message 



    # 文件权限情况
    def check_passwd_file_status(self):
        message = {}
        message['status'] = 0
        message['data'] = {}
        files = ['/etc/passwd','/etc/shadow']
        ID = 1

        for file in files:
            if not os.path.exists(file):
                continue
            command = f"ls -l {file} 2> /dev/null | " + " awk '{print $1}'"
            content = runCommand(command).decode('utf-8')
            if len(content):continue
            if file == '/etc/passwd' and content != '-rw-r--r--':
                message['status'] = 1
                message['data'][ID] = {'file':'/etc/passwd','content':content} 
            if file == '/etc/shadow' and content != '----------':
                message['status'] = 1
                message['data'][ID] = {'file':'/etc/passwd','content':content} 
        return message


def run(config_content):
    information = AccountInfo(config_content)

    console(4)
    console(0,'开始检查账户安全')

    console(0,"检查账户安全：")
    if len(information.special_accounts["evil_users"]) != 0:
        console(3,"检测到UID为0的非root账户：")
        for evil_user in information.special_accounts["evil_users"]:
            console(3,f"{evil_user} 为存在于主机上的UID为0的用户")
    else:
        console(1,"不存在UID为0的非root账户")


    if information.special_accounts['status'] == 0:
        console(3,f"出现错误：{information.special_accounts['exception']}")
    else:
        if len(information.special_accounts["empty_users"]) != 0:
            console(3,"检测存在空口令账户：")
            for evil_user in information.special_accounts["empty_users"]:
                console(3,f"{evil_user} 为存在于主机上的空口令账户")
        else:
            console(1,"不存在空口令账户")


    console(0,'检查口令策略相关信息：')
    if information.password_policy['status'] == 0:
        console(2,f"未检测到存在口令策略 {information.password_policy['filepath']} 存在")
    else:
        if information.password_policy['pass_max'] and int(information.password_policy['pass_max']) <= int(config_content['policy']['pass_max']):
            console(1,f"口令最大生存周期符合要求 现周期为：{information.password_policy['pass_max']}")
        else:
            console(2,f"口令最大生存周期不符合要求，建议小于等于{config_content['policy']['pass_max']}天 现周期为：{information.password_policy['pass_max']}")

        if information.password_policy['pass_min'] and int(information.password_policy['pass_min']) >= int(config_content['policy']['pass_min']):
            console(1,f"口令最小更改时间符合要求 现周期为：{information.password_policy['pass_min']}")
        else:
            console(2,f"口令最小更改时间不符合要求，建议大于等于{config_content['policy']['pass_min']}天 现周期为：{information.password_policy['pass_min']}")
        
        if information.password_policy['pass_len'] and int(information.password_policy['pass_len']) <= int(config_content['policy']['pass_len']):
            console(1,f"口令最小长度符合要求 现周期为：{information.password_policy['pass_len']}")
        else:
            console(2,f"口令最小长度不符合要求，建议大于等于{config_content['policy']['pass_len']}天 现周期为：{information.password_policy['pass_len']}")
        
        if information.password_policy['pass_age'] and int(information.password_policy['pass_age']) >= int(config_content['policy']['pass_age']):
            console(1,f"口令过期警告时间符合要求 现周期为：{information.password_policy['pass_age']}")
        else:
            console(2,f"口令过期警告时间不符合要求，建议小于等于{config_content['policy']['pass_age']}天并小于口令最大生存周期 现周期为：{information.password_policy['pass_age']}")

    console(0,'检查账号自动注销设置：')
    if information.TMOUT['status'] == 0:
        console(2,f"未检测到存在口令策略 {information.TMOUT['filepath']} 存在")
    else:
        if information.TMOUT['TMOUT_Time']:
            if int(information.TMOUT['TMOUT_Time']) < int(config_content['TMOUT']['timeout']):
                console(1,f"账号自动注销设置符合要求，时间为{information.TMOUT['TMOUT_Time']}")
            else:
                console(2,f"账号自动注销设置不符合要求，时间为{information.TMOUT['TMOUT_Time']}")
        else:
            console(2,f"未设置TMOUT账号自动注销")

    console(0,"检查当前登陆的用户：")
    if information.current_user['status'] == 0:
        console(1,'当前没有登陆的用户')
    else:
        for userinfo in information.current_user:
            console(2,f"当前登陆的用户为：{userinfo['current_user']} . 登陆时间为 {current_user['login_time']} . 登陆来源为： {current_user['remote_ip']} ." )

    console(0,"检查当前sudo用户")
    if information.sudo_status['status'] == 0 :
        console(1,"未发现sudo权限用户")
    else:
        for key,value in information.sudo_status['data'].items():
            console(2,f"发现sudo权限用户 文件 {value['file']} . 用户 {value['content']} ")

    console(0,"开始检查免密登录公钥情况")
    if information.authorized_keys_status['status'] == 0:
        console(1,"免密登录公钥情况正常")
    else:
        for key,value in information.authorized_keys_status['data']:
            console(2,f"发现免密登陆证书 路径：{value['file']} . 客户端 {value['content']} ")

    console(0,"开始检查密码文件权限情况")
    if information.passwd_file_status['status'] == 0:
        console(1,"密码文件权限情况正常")
    else:
        for key,value in information.passwd_file_status['data']:
            console(2,f"{value['file']}文件权限情况不正常 权限为 {value['content']}")

    console(4)

    del information