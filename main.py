# -*- coding:utf-8 -*-

import sys
import yaml
from multiprocessing import Pool

from common.Console import console,debug

# plugins
from plugins import SysInfo
from plugins import Account
from plugins import File
from plugins import System
from plugins import CommandHistory
from plugins import Process
from plugins import NetWork 
from plugins import Backdoor
from plugins import SysLog

if sys.version_info[0] < 3: # < 3.0
    raise Exception('Must be using at least Python 3')

try:
    reload(sys)
    sys.setdefaultencoding('utf8')
except:
    pass


def check(config_content):
    # 系统信息
    SysInfo.run()

    pool = Pool(4)
    missions = {}

    # 系统初始化项检查
    if config_content['System']['enable'] == 1:
        missions[System.run] =  config_content['System']

    # 账户信息检查
    if config_content['Account']['enable'] == 1:
        missions[Account.run]= config_content['Account']

    # 文件扫描
    if config_content['File']['enable'] == 1:
        missions[File.run] = config_content['File']

    # 用户历史命令分析
    if config_content['CommandHistory']['enable'] == 1:
        missions[CommandHistory.run] = config_content['CommandHistory']

    # 进程分析
    if config_content['Process']['enable'] == 1:
        missions[Process.run] = config_content['Process']

    # 网络
    if config_content['NetWork']['enable'] == 1:
        missions[NetWork.run] = config_content['NetWork']

    # 后门分析
    if config_content['Backdoor']['enable'] == 1:
        missions[Backdoor.run] = config_content['Backdoor']

    for key,value in missions.items():
        pool.apply_async(key, (value,))


    pool.close()
    pool.join()
    console(4)
    console(0,"检查完毕")
    console(4)


if __name__ == '__main__':
    banner = '''
     _   _           _        ____                       _ _
    | | | | ___  ___| |_     / ___|  ___  ___ _   _ _ __(_) |_ _   _
    | |_| |/ _ \/ __| __|    \___ \ / _ \/ __| | | | '__| | __| | | |
    |  _  | (_) \__ \ |_      ___) |  __/ (__| |_| | |  | | |_| |_| |
    |_| |_|\___/|___/\__|    |____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                               |___/
    '''
    print(banner)

    config_file = open('config.yml', 'r', encoding="utf-8")
    config_content = yaml.load(config_file.read(),Loader=yaml.FullLoader)
    config_file.close()

    #try:
    check(config_content)
    # except KeyboardInterrupt:
    #     sys.exit(-1)