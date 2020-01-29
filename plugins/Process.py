# -*- coding:utf-8 -*-

import sys
sys.path.append('../')
import os

from common.Console import console,debug
from common.RunCommand import runCommand
from common.EvilAnalyze import check_shell
from common.StringCommon import analysis_string

class ProcessInfo():

    def __init__(self,config_content):
        self.config_content = config_content

        self.cpu_status,self.memory_status = self.check_work_status()
        self.hidden_processes = self.check_hidden_process()
        self.reverse_shell_status = self.check_reverse_shell_status()
        self.exe_file_status = self.check_exe_file_status()

    # CPU和内存使用情况
    def check_work_status(self):
        cpu_message = []
        memory_message = []

        max_cpu = self.config_content['work_status']['max_cpu']
        max_mem = self.config_content['work_status']['max_mem']
        normal_service = self.config_content['work_status']['normal_service']

        current_pid = os.getpid()

        # 用户 PID CPU使用率 内存使用率 COMMAND
        command = f"ps aux | grep -v PID | sort -rn -k +3 | head | awk '{{print $1,$2,$3,$4,$11}}'| grep -v '{normal_service}'"
        content = runCommand(command).decode('utf-8').splitlines()
        for line in content:
            info = line.strip().split(' ')
            if int(info[1]) != current_pid:
                if float(info[2]) >= max_cpu:
                    cpu_message.append(info)
                if float(info[3]) >= max_mem:
                    memory_message.append(info)
        return cpu_message,memory_message

    # 检测隐藏进程
    def check_hidden_process(self):
        ''' 比较ps -ef 和 /proc 目录下所有进程 找出隐藏的进程 '''
        message = []

        try:
            # ps -ef 来获取所有pid号
            command =  "ps -ef 2>/dev/null | awk 'NR>1{print $2}'"
            command_processes = runCommand(command).decode('utf-8').splitlines()

            # 扫描 /proc目录
            file_processes = []
            if not os.path.exists('/proc/'):
                return message
            for file in os.listdir('/proc'):
                if file.isdigit():
                    file_processes.append(file)

            # 比较
            hidden_processes = list(set(pid_pro_file).difference(set(pid_process)))
            message = message + hidden_processes
        except:
            pass  
        finally:
            return message

    # 反弹shell进程检查
    def check_reverse_shell_status(self):
        message = {}

        for file in os.listdir('/proc/'):
            if file.isdigit():
                filepath = os.path.join('%s%s%s' % ('/proc/', file, '/cmdline'))
                content = runCommand(f"strings {filepath} 2> /dev/null").decode('utf-8')
                info = analysis_string(content)
                if info:
                    message[filepath] = [file,info]
        return message

    def check_exe_file_status(self):
        message = {}

        if not os.path.exists('/proc/'):
            return message

        try:
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    filepath = os.path.join('%s%s%s' % ('/proc/', file, '/exe'))
                    if (not os.path.islink(filepath)) or (not os.path.exists(filepath)):
                        continue
                    info = analysis_file(filepath)
                    if info:
                        lnstr = os.readlink(filepath)
                        message[lnstr] = info
        except:
            pass
        finally:
            return message
def run(config_content):
    information = ProcessInfo(config_content)

    console(4)
    console(0,"开始进程安全检测")
    console(0,"开始分析占用CPU高的进程：")
    if len(information.cpu_status) == 0:
        console(1,"进程使用CPU正常")
    else:
        for info in information.cpu_status:
            console(3,f"存在超过CPU阈值的进程。所属用户为 {info[0]} . 进程号为 {info[1]} . 占用CPU率为 {info[2]} . 对应命令为 {info[4]} .")

    console(0,"开始分析占用内存高的进程：")
    if len(information.memory_status) == 0:
        console(1,"进程使用CPU正常")
    else:
        for info in information.memory_status:
            console(3,f"存在超过CPU阈值的进程。所属用户为 {info[0]} . 进程号为 {info[1]} . 占用内存率为 {info[2]} . 对应命令为 {info[4]} .")

    console(0,"开始隐藏进程检查：")
    if len(information.hidden_processes) == 0:
        console(1,"未发现隐藏进程")
    else:
        for info in information.hidden_processes:
            console(3,f"发现隐藏进程 进程号为 {info} . 建议人工检查 /proc/{info}/ .")

    console(0,"开始检查是否存在反弹Shell进程")
    if len(information.reverse_shell_status) == 0:
        console(1,"未发现反弹Shell进程")
    else:
        for key,value in information.reverse_shell_status.items():
            console(3,f"发现反弹Shell进程 进程路径 {key} . 进程号为 {value[0]} . 内容为 {value[1]}")
    
    console(0,"开始分析进程的执行文件：")
    if len(information.exe_file_status) == 0:
        console(1,"未发现进程恶意执行文件")
    else:
        for key,value in information.exe_file_status.items():
            console(3,f"发现进程恶意执行文件 进程名： {key} . 内容为 ： {value}")
    console(4)

    del information