#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sys
import os
import re
import ipaddress
import codecs
import time
import pandas as pd
import urllib3
sys.path.append('./classifier4gyoithon')
from GyoiClassifier import DeepClassifier
from GyoiExploit import Metasploit
from GyoiReport import CreateReport

OKBLUE = '\033[96m'
OKGREEN = '\033[92m'
YELLOW = '\033[93m'
ENDC = '\033[0m'


# Identify product name.
def identify_product(categoy, target_url, response):
    product_list = []
    reason_list = []
    full_path = os.path.dirname(os.path.abspath(__file__))
    file_name = 'signature_' + categoy + '.txt'
    try:
        with codecs.open(os.path.join(full_path + '/signatures/', file_name), 'r', 'utf-8') as fin:
            matching_patterns = fin.readlines()
            for pattern in matching_patterns:
                items = pattern.replace('\r', '').replace('\n', '').split('@')
                keyword_list = []
                product = items[0]
                signature = items[1]
                list_match = re.findall(signature, response, flags=re.IGNORECASE)
                if len(list_match) != 0:
                    # Output result (header)
                    print('-' * 42)

                    keyword_list.append(list_match)
                    print(OKBLUE + '[-] category    : {0}\n'
                                   '    product     : {1}\n'
                                   '    reason      : {2}\n'
                                   '    target url  : {3}'.format(categoy, product, keyword_list, target_url + ENDC))
                    product_list.append(product)
                    reason_list.append(keyword_list)
    except Exception as err:
        print('Exception: {0}'.format(err))
    return product_list, reason_list


# Classifier product name using signatures.
def classifier_signature(ip_addr, port, target_url, response, log_file):
    ip_list = [ip_addr]
    port_list = [port]
    vhost_list = [ip_addr]
    judge_list = ['-']
    version_list = ['-']
    reason_list = ['-']
    scan_type_list = ['-']
    ua_list = ['-']
    http_ver_list = ['-']
    ssl_list = ['-']
    sni_list = ['-']
    url_list = ['-']
    log_list = [os.path.join('gyoithon', log_file)]
    product_list = ['-']
    for category in ['os', 'web', 'framework', 'cms']:
        products, keywords = identify_product(category, target_url, response)
        for product, keyword in zip(products, keywords):
            ip_list.append(ip_addr)
            port_list.append(port)
            vhost_list.append(ip_addr)
            judge_list.append(category + ':' + str(product))
            version_list.append('-')
            reason_list.append(keyword)
            scan_type_list.append('[ip]')
            ua_list.append('-')
            http_ver_list.append('HTTP/1.1')
            ssl_list.append('-')
            sni_list.append('-')
            url_list.append(target_url)
            log_list.append(os.path.join('gyoithon', log_file))
            product_list.append(product)

    # logging.
    series_ip = pd.Series(ip_list)
    series_port = pd.Series(port_list)
    series_vhost = pd.Series(vhost_list)
    series_judge = pd.Series(judge_list)
    series_version = pd.Series(version_list)
    series_reason = pd.Series(reason_list)
    series_scan_type = pd.Series(scan_type_list)
    series_ua = pd.Series(ua_list)
    series_http_ver = pd.Series(http_ver_list)
    series_ssl = pd.Series(ssl_list)
    series_sni = pd.Series(sni_list)
    series_url = pd.Series(url_list)
    series_log = pd.Series(log_list)
    df = pd.DataFrame({'ip': series_ip,
                       'port': series_port,
                       'vhost': series_vhost,
                       'judge': series_judge,
                       'judge_version': series_version,
                       'reason': series_reason,
                       'scantype': series_scan_type,
                       'ua': series_ua,
                       'version': series_http_ver,
                       'ssl': series_ssl,
                       'sni': series_sni,
                       'url': series_url,
                       'log': series_log},
                      columns=['ip', 'port', 'vhost', 'judge', 'judge_version', 'reason',
                               'scantype', 'ua', 'version', 'ssl', 'sni', 'url', 'log'])
    saved_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gyoithon')
    df.sort_values(by='port', ascending=False).to_csv(os.path.join(saved_path, 'webconf.csv'))
    return product_list


# Check IP address format.
def is_valid_ip(arg):
    try:
        ipaddress.ip_address(arg)
        return True
    except ValueError:
        return False


# Check argument values.
def check_arg_value(ip_addr, port, path):
    # Check IP address.
    if is_valid_ip(ip_addr) is False:
        print('[*] Invalid IP address: {0}'.format(ip_addr))
        return False

    # Check port number.
    if port.isdigit() is False:
        print('[*] Invalid port number: {0}'.format(port))
        return False
    elif (int(port) < 1) or (int(port) > 65535):
        print('[*] Invalid port number: {0}'.format(port))
        return False

    # Check virtual host.
    if isinstance(path, str) is False and isinstance(path, int) is False:
        print('[*] Invalid vhost: {0}'.format(path))
        return False

    return True


# Get target information.
def get_target_info():
    full_path = os.path.dirname(os.path.abspath(__file__))
    ip_addr = []
    port = []
    path = []
    try:
        with codecs.open(os.path.join(full_path, 'host.txt'), 'r', 'utf-8') as fin:
            targets = fin.readlines()
            for target in targets:
                items = target.replace('\r', '').replace('\n', '').split(' ')
                ip_addr.append(items[0])
                port.append(items[1])
                path.append(items[2])
    except Exception as err:
        print('Invalid file: {0}'.format(err))

    return ip_addr, port, path


# Display banner.
def show_banner():
    banner = """
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 ██████╗██╗   ██╗ ██████╗ ██╗████████╗██╗  ██╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔═══██╗██║╚══██╔══╝██║  ██║██╔═══██╗████╗  ██║
██║  ███╗╚████╔╝ ██║   ██║██║   ██║   ███████║██║   ██║██╔██╗ ██║
██║   ██║ ╚██╔╝  ██║   ██║██║   ██║   ██╔══██║██║   ██║██║╚██╗██║
╚██████╔╝  ██║   ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
""" + 'by ' + os.path.basename(__file__)
    print(OKGREEN + banner + ENDC)
    print()


# main.
if __name__ == '__main__':
    show_banner()

    # Get target information.
    ip_list, port_list, path_list = get_target_info()

    # Check parameters.
    product_list = []
    full_path = os.path.dirname(os.path.abspath(__file__))
    for idx in range(len(ip_list)):
        if check_arg_value(ip_list[idx], port_list[idx], path_list[idx]) is False:
            print('Invalid parameter: {0}, {1}, {2}'.format(ip_list[idx], port_list[idx], path_list[idx]))

        # Get HTTP responses.
        log_file = 'get_' + ip_list[idx] + '_' + str(port_list[idx]) + '_ip.log'
        con = urllib3.PoolManager()
        for scheme in ['http://', 'https://']:
            target_url = scheme + ip_list[idx] + ':' + port_list[idx] + path_list[idx]
            response = ''
            try:
                # Get HTTP headers and body.
                res = con.request('GET', target_url)
                headers = dict(res.headers)
                for header in headers.keys():
                    response += header + ': ' + headers[header].replace('"', '') + '\n'
                response += '\n' + res.data.decode('utf-8') + '\n'

                with codecs.open(os.path.join(full_path + '/gyoithon/', log_file), 'a', 'utf-8') as fout:
                    fout.write(response)
            except Exception as err:
                print('[*] Exception: {0}'.format(err))
                continue

            # Judge product name using string matching.
            products = classifier_signature(ip_list[idx], port_list[idx], target_url, response, log_file)
            for product in products:
                product_list.append(product)

        # Classifier using Machine Learning.
        classifier = DeepClassifier()
        products = classifier.analyzer(ip_list[idx], int(port_list[idx]), ip_list[idx])
        for product in products:
            product_list.append(product)
        time.sleep(5)

        # Exploit using Metasploit.
        product_list = list(set(product_list))
        for product in product_list:
            metasploit = Metasploit()
            metasploit.exploit({'ip': ip_list[idx], 'port': int(port_list[idx]), 'prod_name': product})

    # Create Report.
    report = CreateReport()
    report.create_report()
    print(os.path.basename(__file__) + ' finish!!')
