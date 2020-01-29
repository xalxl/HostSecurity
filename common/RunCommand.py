# -*- coding:utf-8 -*-

import subprocess

def runCommand(command):
    stdout,stderr = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).communicate()
    return stdout