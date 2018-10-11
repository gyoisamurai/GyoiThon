#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import re
import ipaddress
import codecs
import time
import pandas as pd
import urllib3
from urllib3 import util
from classifier4gyoithon.GyoiClassifier import DeepClassifier
from classifier4gyoithon.GyoiExploit import Metasploit
from classifier4gyoithon.GyoiReport import CreateReport
from util import Utilty

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Identify product name using signature.
def identify_product(categoy, target_url, response, utility):
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
                    keyword_list.append(list_match)
                    utility.print_message(OK, 'category    : {}'.format(categoy))
                    utility.print_message(OK, 'product     : {}'.format(product))
                    utility.print_message(OK, 'reason      : {}'.format(keyword_list))
                    utility.print_message(OK, 'target url  : {}'.format(target_url))
                    utility.print_message(NONE, '-' * 42)
                    product_list.append(product)
                    reason_list.append(keyword_list)
    except Exception as err:
        utility.print_exception(err, '{}'.format(err))
    return product_list, reason_list


# Classifier product name using signatures.
def classifier_signature(ip_addr, port, target_url, response, log_file, utility):
    utility.print_message(NOTE, 'Analyzing gathered HTTP response using Signature.')
    ip_list = []
    port_list = []
    vhost_list = []
    judge_list = []
    version_list = []
    reason_list = []
    scan_type_list = []
    ua_list = []
    http_ver_list = []
    ssl_list = []
    sni_list = []
    url_list = []
    log_list = []
    product_list = []
    for category in ['os', 'web', 'framework', 'cms']:
        products, keywords = identify_product(category, target_url, response, utility)
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
            log_list.append(log_file)
            product_list.append(product)

    if len(product_list) == 0:
        utility.print_message(WARNING, 'Product Not Found.')
        return []

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
    df.sort_values(by='port', ascending=False).to_csv(os.path.join(saved_path, 'webconf.csv'),
                                                      mode='a',
                                                      header=False,
                                                      index=False)
    return product_list


# Create webconf.csv
def create_webconf(ip_addr, port, log_file):
    utility.print_message(NOTE, 'Create "webconf.csv".')
    series_ip = pd.Series([ip_addr])
    series_port = pd.Series([str(port)])
    series_vhost = pd.Series([ip_addr])
    series_judge = pd.Series(['-'])
    series_version = pd.Series(['-'])
    series_reason = pd.Series(['-'])
    series_scan_type = pd.Series(['-'])
    series_ua = pd.Series(['-'])
    series_http_ver = pd.Series(['-'])
    series_ssl = pd.Series(['-'])
    series_sni = pd.Series(['-'])
    series_url = pd.Series(['-'])
    series_log = pd.Series([log_file])
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
    df.sort_values(by='port', ascending=False).to_csv(os.path.join(saved_path, 'webconf.csv'), index=False)


# Check IP address format.
def is_valid_ip(arg):
    try:
        ipaddress.ip_address(arg)
        return True
    except ValueError:
        return False


# Check argument values.
def check_arg_value(ip_addr, port, path, utility):
    # Check IP address.
    if is_valid_ip(ip_addr) is False:
        utility.print_message(FAIL, 'Invalid IP address: {}'.format(ip_addr))
        return False

    # Check port number.
    if port.isdigit() is False:
        utility.print_message(FAIL, 'Invalid port number: {}'.format(port))
        return False
    elif (int(port) < 1) or (int(port) > 65535):
        utility.print_message(FAIL, 'Invalid port number: {}'.format(port))
        return False

    # Check path.
    if isinstance(path, str) is False and isinstance(path, int) is False:
        utility.print_message(FAIL, 'Invalid path: {}'.format(path))
        return False

    return True


# Get target information.
def get_target_info(utility):
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
        utility.print_message(FAIL, 'Invalid file: {}'.format(err))

    return ip_addr, port, path


# Display banner.
def show_banner(utility):
    banner = """
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 ██████╗██╗   ██╗ ██████╗ ██╗████████╗██╗  ██╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔═══██╗██║╚══██╔══╝██║  ██║██╔═══██╗████╗  ██║
██║  ███╗╚████╔╝ ██║   ██║██║   ██║   ███████║██║   ██║██╔██╗ ██║
██║   ██║ ╚██╔╝  ██║   ██║██║   ██║   ██╔══██║██║   ██║██║╚██╗██║
╚██████╔╝  ██║   ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  (beta)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
""" + 'by ' + os.path.basename(__file__)
    utility.print_message(NONE, banner)
    show_credit(utility)
    time.sleep(3.0)


# Show credit.
def show_credit(utility):
    credit = u"""
       =[ GyoiThon v0.0.1-beta                               ]=
+ -- --=[ Author  : Gyoiler (@gyoithon)                      ]=--
+ -- --=[ Website : https://github.com/gyoisamurai/GyoiThon/ ]=--
    """
    utility.print_message(NONE, credit)


# main.
if __name__ == '__main__':
    utility = Utilty()
    show_banner(utility)

    # Get target information.
    ip_list, port_list, path_list = get_target_info(utility)

    # Check parameters.
    product_list = []
    full_path = os.path.dirname(os.path.abspath(__file__))
    for idx in range(len(ip_list)):
        if check_arg_value(ip_list[idx], port_list[idx], path_list[idx], utility) is False:
            utility.print_message(FAIL, 'Invalid parameter: {}, {}, {}'.format(ip_list[idx],
                                                                               port_list[idx],
                                                                               path_list[idx]))

        # Start Spider.
        scheme = ['http', 'https']
        web_target_info = utility.run_spider(scheme, ip_list[idx], port_list[idx], path_list[idx])

        # Get HTTP responses.
        log_file = os.path.join(full_path + '/gyoithon/', 'get_' + ip_list[idx] + '_' + str(port_list[idx]) + '_ip.log')
        create_webconf(ip_list[idx], port_list[idx], log_file)
        for target in web_target_info:
            for target_url in target[2]:
                # Check target url.
                parsed = None
                try:
                    parsed = util.parse_url(target_url)
                except Exception as err:
                    utility.print_exception(err, 'Parsed error: {}'.format(target_url))
                    continue

                # Get HTTP response (header + body).
                response = ''
                http = urllib3.PoolManager(timeout=utility.http_timeout)
                try:
                    utility.print_message(OK, '{}  {}'.format(utility.get_current_date('%Y-%m-%d %H:%M:%S'),
                                                              target_url))
                    res = http.request('GET', target_url)
                    for header in res.headers.items():
                        response += header[0] + ': ' + header[1] + '\r\n'
                    response += '\r\n\r\n' + res.data.decode('utf-8')

                    # Write log.
                    with codecs.open(log_file, 'w', 'utf-8') as fout:
                        fout.write(response)
                except Exception as err:
                    utility.print_exception(err, 'Target URL: {}'.format(target_url))
                    continue

                # Judge product name using string matching.
                products = classifier_signature(ip_list[idx], port_list[idx], target_url, response, log_file, utility)
                for product in products:
                    product_list.append(product)

                # Classifier using Machine Learning.
                classifier = DeepClassifier()
                products = classifier.analyzer(ip_list[idx], int(port_list[idx]), ip_list[idx], False, target_url)
                for product in products:
                    product_list.append(product)
                time.sleep(0.5)

        # Exploit using Metasploit.
        product_list = list(set(product_list))
        for product in product_list:
            metasploit = Metasploit()
            metasploit.exploit({'ip': ip_list[idx], 'port': int(port_list[idx]), 'prod_name': product})

    # Create Report.
    report = CreateReport()
    report.create_report()
    print(os.path.basename(__file__) + ' finish!!')
