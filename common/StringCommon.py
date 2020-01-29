# -*- coding:utf-8 -*-

import os

from common.EvilAnalyze import check_shell,check_ip
from common.FileCommon import analysis_file

from common.Console import debug

def analysis_string(content):
    content = content.replace('\n', '')
    if check_shell(content):
        return content # 有反弹Shell特征
    # IP操作类
    data = check_ip(content)
    if data:
        return data
    # 文件操作
    for file in content.split(' '):
        if not os.path.exists(file):
            continue
        elif os.path.isdir(file):
            continue
        else:
            if analysis_file(file):
                return content
    return False