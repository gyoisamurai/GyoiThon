#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import codecs
import configparser
import pickle
import docopt
import ipaddress
import pandas as pd
import urllib3
from urllib3 import util
from .NaiveBayes import NaiveBayes
sys.path.append('../')
from util import Utilty

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class DeepClassifier:
    def __init__(self):
        # Read config.ini.
        self.utility = Utilty()
        config = configparser.ConfigParser()
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        try:
            config.read(os.path.join(self.full_path, 'config.ini'))
        except FileExistsError as err:
            self.utility.print_exception(err, 'File exists error: {0}'.format(err))
            sys.exit(1)
        self.category_type = config['Common']['category']
        self.train_path = os.path.join(self.full_path, config['GyoiClassifier']['train_path'])
        self.trained_path = os.path.join(self.full_path, config['GyoiClassifier']['trained_path'])
        self.train_os_in = os.path.join(self.train_path, config['GyoiClassifier']['train_os_in'])
        self.train_os_out = os.path.join(self.trained_path, config['GyoiClassifier']['train_os_out'])
        self.train_web_in = os.path.join(self.train_path, config['GyoiClassifier']['train_web_in'])
        self.train_web_out = os.path.join(self.trained_path, config['GyoiClassifier']['train_web_out'])
        self.train_framework_in = os.path.join(self.train_path, config['GyoiClassifier']['train_framework_in'])
        self.train_framework_out = os.path.join(self.trained_path, config['GyoiClassifier']['train_framework_out'])
        self.train_cms_in = os.path.join(self.train_path, config['GyoiClassifier']['train_cms_in'])
        self.train_cms_out = os.path.join(self.trained_path, config['GyoiClassifier']['train_cms_out'])
        self.wait_for_banner = float(config['GyoiClassifier']['wait_for_banner'])
        self.maximum_display_num = int(config['GyoiClassifier']['maximum_display_num'])
        self.summary_path = os.path.join(self.full_path, config['GyoiThon']['summary_path'])
        self.summary_file = os.path.join(self.summary_path, config['GyoiThon']['summary_file'])
        return

    # Analysis using ML.
    def analyzer(self, target_ip='', target_port=0, target_vhost='', silent=False, target_url='', target_response=''):
        self.utility.print_message(NOTE, 'Analyzing gathered HTTP response using Machine Learning.')
        identified_list = []
        target_info = ''
        target_log = ''
        analyzing_text = ''
        if target_response == '':
            # Get GyoiThon's summary.
            df_origin = pd.read_csv(self.summary_file, encoding='utf-8').fillna('')
            df_selected_summary = df_origin[(df_origin['ip'] == target_ip) &
                                            (df_origin['port'] == target_port) &
                                            (df_origin['vhost'] == target_vhost)]

            # Get log file (webconf.csv)
            logfile_path = os.path.join(self.root_path, df_selected_summary.at[0, 'log'])
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
        # If silent mode is True, hidden target information.
        if silent is True:
            self.utility.print_message(WARNING, 'target host : *** hidden for silent mode. ***')
            self.utility.print_message(WARNING, 'target url  : *** hidden for silent mode. ***')
            self.utility.print_message(WARNING, 'target log  : *** hidden for silent mode. ***')
        else:
            self.utility.print_message(WARNING, 'target host : {}'.format(target_info))
            self.utility.print_message(WARNING, 'target url  : {}'.format(target_url))
            self.utility.print_message(WARNING, 'target log  : {}'.format(target_log))
        self.utility.print_message(OK, 'judge :')

        # Predict product name each category (OS, Middleware, CMS..).
        list_category = self.category_type.split('@')
        print('-' * 42)
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
                self.utility.print_message(FAIL, 'Choose category is not found.')
                exit(1)

            # Predict product name.
            product, prob, keyword_list, classified_list = nb.classify(analyzing_text)

            # Output result of prediction (body).
            # If no feature, result is unknown.
            if len(keyword_list) == 0:
                self.utility.print_message(NOTE, 'category : {}'.format(category))
                self.utility.print_message(WARNING, 'product  : unknown')
                self.utility.print_message(WARNING, 'too low probability.')
            else:
                sorted_classified_list = sorted(classified_list, key=lambda x: x[1], reverse=True)
                self.utility.print_message(NOTE, 'category : {}'.format(category))
                for idx, item in enumerate(sorted_classified_list):
                    add_flag = True
                    if idx >= self.maximum_display_num:
                        break
                    # Delete duplicated result.
                    reason_list = []
                    for reason in item[2]:
                        reason_list.append(list(set(reason)))
                    # # If no feature, reason is "too few features".
                    if len(item[2]) == 0:
                        reason_list = 'too few features..'
                        add_flag = False
                    self.utility.print_message(NOTE, 'ranking {}'.format(idx + 1))
                    self.utility.print_message(OK, 'product     : {}'.format(item[0]))
                    self.utility.print_message(OK, 'probability : {}'.format(round(item[1] * 100.0, 4)))
                    self.utility.print_message(OK, 'reason      : {}'.format(reason_list))
                    # Add product for Exploit.
                    identified_list.append(item[0])
            self.utility.print_message(NONE, '-' * 42)

        # Output result of prediction (footer).
        self.utility.print_message(NOTE, 'done {}'.format(os.path.basename(__file__)))

        return list(set(identified_list))

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


# Define command option.
__doc__ = """{f}
Usage:
    {f} (-t <ip_addr> | --target <ip_addr>) (-p <port> | --port <port>) (-v <vhost> | --vhost <vhost>) [(-u <url> | --url <url>)]
    {f} -h | --help
Options:
    -t --target   Require  : IP address of target server.
    -p --port     Require  : Port number of target server.
    -v --vhost    Require  : Virtual Host of target server.
    -u --url      Optional : Full URL for direct access.
    -h --help     Optional : Show this screen and exit.
""".format(f=__file__)


# Parse command arguments.
def command_parse():
    args = docopt.docopt(__doc__)
    ip_addr = args['<ip_addr>']
    port = args['<port>']
    vhost = args['<vhost>']
    url = args['<url>']
    return ip_addr, port, vhost, url


# Check IP address format.
def is_valid_ip(arg):
    try:
        ipaddress.ip_address(arg)
        return True
    except ValueError:
        return False


# Check argument values.
def check_arg_value(ip_addr, port, vhost, url=None):
    # Check IP address.
    if is_valid_ip(ip_addr) is False:
        Utilty().print_message(FAIL, 'Invalid IP address: {}'.format(ip_addr))
        return False

    # Check port number.
    if port.isdigit() is False:
        Utilty().print_message(FAIL, 'Invalid port number: {}'.format(port))
        return False
    elif (int(port) < 1) or (int(port) > 65535):
        Utilty().print_message(FAIL, 'Invalid port number: {}'.format(port))
        return False

    # Check virtual host.
    if isinstance(vhost, str) is False and isinstance(vhost, int) is False:
        Utilty().print_message(FAIL, 'Invalid vhost: {}'.format(vhost))
        return False

    # Check url.
    if url is not None:
        target = util.parse_url(url)
        if 'http' not in target.scheme:
            Utilty().print_message(FAIL, 'Invalid scheme : {}.'.format(target.scheme))
            return False
        if target.netloc == '':
            Utilty().print_message(FAIL, 'Invalid fqdn : {}.'.format(target.netloc))
            return False

    return True


if __name__ == '__main__':
    # Get command arguments.
    ip_addr, port, vhost, url = command_parse()

    # Check argument values.
    if check_arg_value(ip_addr, port, vhost, url) is False:
        Utilty().print_message(FAIL, 'Invalid argument.')
        sys.exit(1)

    # Get target's response.
    response = ''
    if url is not None:
        target = util.parse_url(url)
        target_url = target.geturl()
        con = urllib3.PoolManager()
        try:
            # Get HTTP headers and body.
            res = con.request('GET', target_url)
            headers = dict(res.headers)
            for header in headers.keys():
                response += header + ': ' + headers[header].replace('"', '') + '\n'
            response += '\n' + res.data.decode('utf-8') + '\n'
        except Exception as err:
            Utilty().print_message(FAIL, 'Connection error: {}'.format(err))
            sys.exit(1)

    # Execute classifier.
    classifier = DeepClassifier()
    classifier.analyzer(ip_addr, int(port), vhost, False, url, response)
    Utilty().print_message(NOTE, os.path.basename(__file__) + ' finish!!')
