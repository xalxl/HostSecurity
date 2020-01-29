# -*- coding:utf-8 -*-

import sys
sys.path.append('../')


class SysLogInfo():

    def __init__(self,config_content):
        self.config_content = config_content


def run(config_content):
    information = SysLogInfo(config_content)

    

    del information