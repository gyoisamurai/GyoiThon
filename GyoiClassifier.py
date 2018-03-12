#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import codecs
import configparser
import pickle
import argparse
import pandas as pd
from urllib.parse import urlparse
from urllib.request import urlopen
from NaiveBayes import NaiveBayes

OKBLUE = '\033[96m'
OKGREEN = '\033[92m'
YELLOW = '\033[93m'
ENDC = '\033[0m'


class DeepClassifier:
    def __init__(self):
        # Read config.ini.
        config = configparser.ConfigParser()
        try:
            config.read('./classifier4gyoithon/config.ini')
        except FileExistsError as err:
            print('File exists error: {0}', err)
            sys.exit(1)
        self.category_type = config['Common']['category']
        self.train_os_in = config['GyoiClassifier']['train_os_in']
        self.train_os_out = config['GyoiClassifier']['train_os_out']
        self.train_web_in = config['GyoiClassifier']['train_web_in']
        self.train_web_out = config['GyoiClassifier']['train_web_out']
        self.train_framework_in = config['GyoiClassifier']['train_framework_in']
        self.train_framework_out = config['GyoiClassifier']['train_framework_out']
        self.train_cms_in = config['GyoiClassifier']['train_cms_in']
        self.train_cms_out = config['GyoiClassifier']['train_cms_out']
        self.wait_for_banner = float(config['GyoiClassifier']['wait_for_banner'])
        self.maximum_display_num = int(config['GyoiClassifier']['maximum_display_num'])
        self.summary_path = config['GyoiThon']['summary_path']
        return

    def show_start_banner(self):
        thontak = """
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
　　███╗   ███╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗███████╗
　　████╗ ████║██╔══██╗██╔════╝██║  ██║██║████╗  ██║██╔════╝
　　██╔████╔██║███████║██║     ███████║██║██╔██╗ ██║█████╗
　　██║╚██╔╝██║██╔══██║██║     ██╔══██║██║██║╚██╗██║██╔══╝
　　██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║██║ ╚████║███████╗
　　╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝ 

　██╗     ███████╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ 
　██║     ██╔════╝██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ 
　██║     █████╗  ███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
　██║     ██╔══╝  ██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
　███████╗███████╗██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
　╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
　　   __      _   _      _   _                 _        _    
　　  / /  ___| |_( )__  | |_| |__   ___  _ __ | |_ __ _| | __
　　 / /  / _ \ __|/ __| | __| '_ \ / _ \| '_ \| __/ _` | |/ /
　　/ /__|  __/ |_ \__ \ | |_| | | | (_) | | | | || (_| |   < 
　　\____/\___|\__||___/  \__|_| |_|\___/|_| |_|\__\__,_|_|\_\
\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
""" + 'by ' + os.path.basename(__file__)
        print(OKGREEN + thontak + ENDC)
        print()

    # Analysis using ML.
    def analyzer(self, target_ip='', target_port=0, target_vhost='', silent=False, target_url='', target_response=''):
        # Display banner.
        self.show_start_banner()
        time.sleep(5)
        time.sleep(float(self.wait_for_banner))

        target_info = ''
        target_log = ''
        analyzing_text = ''
        if target_response == '':
            # GyoiThonのsummary取得
            df_origin = pd.read_csv(self.summary_path, encoding='utf-8').fillna('')
            df_selected_summary = df_origin[(df_origin['ip'] == target_ip) &
                                            (df_origin['port'] == target_port) &
                                            (df_origin['vhost'] == target_vhost)]

            # Get log file (webconf.csv)
            logfile_path = df_selected_summary.iloc[0, 12]
            fin = codecs.open(logfile_path, 'r', encoding='utf-8')
            analyzing_text = fin.read()
            fin.close()
            target_info = target_vhost + '(' + target_ip + '):' + str(target_port)
            target_log = logfile_path
        else:
            target_info = target_url
            target_log = 'not use'
            analyzing_text = target_response

        # Output result (header)
        print('-' * 42)

        # If silent mode is True, hidden target information.
        if silent is True:
            print('target     : *** hidden for silent mode. ***')
            print('target log : *** hidden for silent mode. ***')
        else:
            print('target     : {0}'.format(target_info))
            print('target log : {0}'.format(target_log))
        print()
        print('[+] judge :')

        # Predict product name each category (OS, Middleware, CMS..).
        list_category = self.category_type.split('@')
        for category in list_category:
            # Learning.
            if category == 'os':
                nb = self.train(self.train_os_in, self.train_os_out)
            elif category == 'web server':
                nb = self.train(self.train_web_in, self.train_web_out)
            elif category == 'framework':
                nb = self.train(self.train_framework_in, self.train_framework_out)
            elif category == 'cms':
                nb = self.train(self.train_cms_in, self.train_cms_out)
            else:
                print('Choose category is not found.')
                exit(1)

            # Predict product name.
            product, prob, keyword_list, classified_list = nb.classify(analyzing_text)

            # Output result of prediction (body).
            # If no feature, result is unknown.
            if len(keyword_list) == 0:
                print(YELLOW + '[-] category : {0}\n'
                               '    product  : unknown\n'
                               '    too low maximum probability.'.format(category) + ENDC)
            else:
                sorted_classified_list = sorted(classified_list, key=lambda x: x[1], reverse=True)
                print(OKBLUE + '[-] category : {0}'.format(category) + ENDC)
                for idx, item in enumerate(sorted_classified_list):
                    if idx >= self.maximum_display_num:
                        break
                    # Delete duplicated result.
                    reason_list = []
                    for reason in item[2]:
                        reason_list.append(list(set(reason)))
                    # # If no feature, reason is "too few features".
                    if len(item[2]) == 0:
                        reason_list = 'too few features..'
                    print('    ' + '-' * 5)
                    print(OKBLUE + '    ranking {0}\n'
                                   '    product     : {1}\n'
                                   '    probability : {2} %\n'
                                   '    reason      : {3}'.format(idx + 1, item[0], round(item[1] * 100.0, 4),
                                                                  reason_list) + ENDC)

        # Output result of prediction (footer).
        print('-' * 42)
        print()
        print('[+] done {0}'.format(os.path.basename(__file__)))

    # Execute learning / Get learned data.
    def train(self, in_file, out_file):
        # If existing learned data (pkl), load learned data.
        nb = None
        if os.path.exists(out_file):
            with open(out_file, 'rb') as f:
                nb = pickle.load(f)
        # If no learned data, execute learning.
        else:
            # Read learning data.
            nb = NaiveBayes()
            fin = codecs.open(in_file, 'r', 'utf-8')
            lines = fin.readlines()
            fin.close()
            items = []

            for line in lines:
                words = line[:-2]
                train_words = words.split('@')
                items.append(train_words[1])
                nb.train(train_words[1], train_words[0])

            # Save learned data to pkl file.
            with open(out_file, 'wb') as f:
                pickle.dump(nb, f)
        return nb


if __name__ == '__main__':
    cmd_parser = argparse.ArgumentParser()
    cmd_parser.add_argument('-t',
                            '--target',
                            action='store',
                            nargs=None,
                            const=None,
                            default=None,
                            type=str,
                            metavar=None)
    args = cmd_parser.parse_args()

    target = urlparse(args.target)
    if 'http' not in target.scheme:
        print('Invalid scheme : {0}.'.format(target.scheme))
        sys.exit(0)
    if target.netloc == '':
        print('Invalid fqdn : {0}.'.format(target.netloc))
        sys.exit(0)
    target_url = target.geturl()
    target_response = ''
    try:
        with urlopen(target_url) as furl:
            target_response = str(furl.info()).rstrip()
            target_response += furl.read().decode('utf-8')
    except Exception as err:
        print('Connection error: {0}'.format(err))
        sys.exit(1)

    classifier = DeepClassifier()
    # Debug
    target_ip = '40.115.251.148'
    target_port = 443
    target_vhost = 'www.mbsd.jp'
    classifier.analyzer(target_ip, target_port, target_vhost, target_url, target_response)
