# -*- coding:utf-8 -*-

import os

from common.RunCommand import runCommand
from common.EvilAnalyze import check_shell

def get_current_directory_files(filepath):
    ''' 递归获得一个列表下所有的文件 '''
    files_name = []
    try:
        files = os.listdir(filepath)
        for file in files:
            completely_file = os.path.join(filepath,file)
            if os.path.isdir(completely_file):
                files_name = files_name + get_current_directory_files(completely_file)
            else:
                files_name.append(completely_file)
    except (NotADirectoryError,FileNotFoundError):
        pass
    finally:
        return files_name

def analysis_file(file):
    ''' 恶意文件分析 '''
    try:
        if not os.path.exists(file):
            return  # 文件不存在
        if os.path.isdir(file):
            return # 文件为目录
        if os.path.getsize(file) == 0:
            return  # 文件为空
        if round(os.path.getsize(file) / float(1024 * 1024)) > 10:
            return  # 文件太大

        command = f"strings {file} 2> /dev/null"
        content = runCommand(command).decode('utf-8').splitlines()

        for line in content:
            if check_shell(line):
                return line # 返回反弹Shell内容
            else:
                return  # 正常
    except:
        return # 出现错误