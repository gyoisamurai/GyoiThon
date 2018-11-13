#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import json
import configparser
from urllib3 import util
from subprocess import Popen

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class SpiderControl:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.output_base_path = config['Spider']['output_base_path']
            self.store_path = os.path.join(self.full_path, self.output_base_path)
            self.output_filename = config['Spider']['output_filename']
            self.spider_depth_limit = config['Spider']['depth_limit']
            self.spider_delay_time = config['Spider']['delay_time']
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

        if os.path.exists(self.store_path) is False:
            os.mkdir(self.store_path)

    # Running spider.
    def run_spider(self, protocol, target_ip, target_port, target_path):
        self.utility.write_log(20, '[In] Run spider [{}].'.format(self.file_name))

        # Execute crawling using Scrapy.
        all_targets_log = []
        target_url = protocol + '://' + target_ip + ':' + target_port + target_path
        target_log = [target_url]
        now_time = self.utility.get_current_date('%Y%m%d%H%M%S')
        response_log = protocol + '_' + target_ip + '_' + target_port + '_' + now_time + '.log'
        result_dir = os.path.join(self.utility.modules_dir, self.output_base_path)
        result_path = os.path.join(result_dir, now_time + self.output_filename)
        option = ' -a target_url=' + target_url + ' -a allow_domain=' + target_ip + \
                 ' -a depth_limit=' + self.spider_depth_limit + ' -a delay=' + self.spider_delay_time + \
                 ' -a store_path=' + self.store_path + ' -a response_log=' + response_log + ' -o ' + result_path
        spider_path = os.path.join(self.full_path, 'Gyoi_Spider.py')
        command = 'scrapy runspider ' + spider_path + option
        msg = 'Execute spider : {}.'.format(command)
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)
        proc = Popen(command, shell=True)
        proc.wait()

        # Get crawling result.
        dict_json = {}
        if os.path.exists(result_path):
            with codecs.open(result_path, 'r', encoding='utf-8') as fin:
                target_text = self.utility.delete_ctrl_char(fin.read())
                if target_text != '':
                    dict_json = json.loads(target_text)
                else:
                    self.utility.print_message(WARNING, '[{}] is empty.'.format(result_path))

        # Exclude except allowed domains.
        for idx in range(len(dict_json)):
            items = dict_json[idx]['urls']
            for item in items:
                try:
                    if target_ip == util.parse_url(item).host:
                        target_log.append(item)
                except Exception as e:
                    msg = 'Excepting allowed domain is failure : {}'.format(e)
                    self.utility.print_message(FAIL, msg)
                    self.utility.write_log(30, msg)

        self.utility.write_log(20, 'Get spider result.')
        all_targets_log.append([target_url, os.path.join(self.store_path, response_log), list(set(target_log))])
        self.utility.write_log(20, '[Out] Run spider [{}].'.format(self.file_name))
        return all_targets_log
