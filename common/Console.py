# -*- coding:utf-8 -*-

import time
import sys

# 颜色
YELLO = '\033[33m'
GREEN = '\033[32m'
RED = '\033[31m'
BLUE = '\033[34m' 
WHITE = '\033[37m'
FUCHSIA = '\033[35m'

# 定义输出
def console(status,message=None):
    if status == 0: # 运行中
        print(f"{BLUE}[*] "+ time.strftime('%Y_%m_%d')+ " " + message)
    if status == 1: # 正常
        print(f"{GREEN}[+] "+ time.strftime('%Y_%m_%d')+ " " + message)
    if status == 2: # 警告
        print(f"{YELLO}[!] "+ time.strftime('%Y_%m_%d')+ " " + message)
    if status == 3: # 失败
        print(f"{RED}[x] "+ time.strftime('%Y_%m_%d')+ " " + message)
    if status == 4: # 换行
        print(f"{WHITE}"+"="*50)


def debug(message):
    print(f"{FUCHSIA}[DEBUG] "+"*"*65)
    print(f"{FUCHSIA}[CONTENT] " + str(message))
    print(f"{FUCHSIA}[TYPE] " + str(type(message)))
    sys.exit(0)