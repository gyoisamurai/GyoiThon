#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import sys
import codecs
import time
import re
import random
import glob
import configparser
import urllib3
from docopt import docopt
from urllib3 import util
from util import Utilty
from modules.Gyoi_CloudChecker import CloudChecker
from modules.Gyoi_VersionChecker import VersionChecker
from modules.Gyoi_VersionCheckerML import VersionCheckerML
from modules.Gyoi_CommentChecker import CommentChecker
from modules.Gyoi_ErrorChecker import ErrorChecker
from modules.Gyoi_Report import CreateReport
from modules.Gyoi_PageTypeChecker import PageChecker
from modules.Gyoi_GoogleHack import GoogleCustomSearch
from modules.Gyoi_ContentExplorer import ContentExplorer
from modules.Gyoi_SpiderControl import SpiderControl
from modules.Gyoi_CveExplorerNVD import CveExplorerNVD
from modules.Gyoi_Exploit import Exploit
from modules.Gyoi_Censys import Censys
from modules.Gyoi_Creator import Creator
from modules.Gyoi_Inventory import Inventory
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Get target information.
def get_target_info(full_path, utility):
    msg = utility.make_log_msg(utility.log_in, utility.log_dis, os.path.basename(__file__), note='Get target information')
    utility.write_log(20, msg)
    protocol = []
    fqdn = []
    port = []
    path = []
    try:
        with codecs.open(os.path.join(full_path, 'host.txt'), 'r', 'utf-8') as fin:
            targets = fin.readlines()
            for target in targets:
                items = target.replace('\r', '').replace('\n', '').split(' ')
                if len(items) != 4:
                    utility.print_message(FAIL, 'Invalid target record : {}'.format(target))
                    utility.write_log(30, 'Invalid target record : {}'.format(target))
                    continue
                protocol.append(items[0])
                fqdn.append(items[1])
                port.append(items[2])
                path.append(items[3])
    except Exception as e:
        utility.print_message(FAIL, 'Invalid file: {}'.format(e))
        utility.write_log(30, 'Invalid file: {}'.format(e))

    msg = utility.make_log_msg(utility.log_out, utility.log_dis, os.path.basename(__file__), note='Get target information')
    utility.write_log(20, msg)
    return protocol, fqdn, port, path


# Display banner.
def show_banner(utility):
    banner = """
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 ██████╗██╗   ██╗ ██████╗ ██╗████████╗██╗  ██╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔═══██╗██║╚══██╔══╝██║  ██║██╔═══██╗████╗  ██║
██║  ███╗╚████╔╝ ██║   ██║██║   ██║   ███████║██║   ██║██╔██╗ ██║
██║   ██║ ╚██╔╝  ██║   ██║██║   ██║   ██╔══██║██║   ██║██║╚██╗██║
╚██████╔╝  ██║   ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝   ╚═╝    ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  (beta)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
""" + 'by ' + os.path.basename(__file__)
    utility.print_message(NONE, banner)
    show_credit(utility)
    time.sleep(utility.banner_delay)


# Show credit.
def show_credit(utility):
    credit = u"""
       =[ GyoiThon v0.0.3-beta                               ]=
+ -- --=[ Author  : Gyoiler (@gyoithon)                      ]=--
+ -- --=[ Website : https://github.com/gyoisamurai/GyoiThon/ ]=--
    """
    utility.print_message(NONE, credit)


# Divide log.
def divide_log_size(path, clipping_size, clipping_buff):
    target_logs = []
    target_log = ''
    read_data_size = 0
    clipping_idx = 0

    # Dividing byte size.
    content_length = os.path.getsize(path)
    while read_data_size < content_length:
        with codecs.open(path, 'r', 'utf-8') as fin:
            if clipping_idx != 0:
                # Add buffer size to reading pointer.
                read_data_size -= clipping_buff
            fin.seek(read_data_size)

            # Read data from log file.
            try:
                target_log = fin.read(clipping_size)
            except Exception as e:
                utility.print_exception(e, '{}. Skip this data range.'.format(clipping_idx + 1))
                read_data_size += clipping_size
                clipping_idx += 1
                continue

            # Add to log list.
            target_logs.append(target_log)

            # Update reading pointer.
            read_data_size += len(target_log)

            msg = '{}. Divided log that size is {}'.format(clipping_idx + 1, len(target_log))
            utility.print_message(OK, msg)
            clipping_idx += 1

    return target_logs


# Divide data.
def divide_data_size(data, clipping_size, clipping_buff):
    target_datas = []

    # Dividing byte size.
    target_datas.append(data[:clipping_size])
    if len(data) > clipping_size:
        target_datas.extend([data[i-clipping_buff: i + clipping_size] for i in range(clipping_size,
                                                                                     len(data),
                                                                                     clipping_size)])
    return target_datas


# Define command option.
__doc__ = """{f}
usage:
    {f} [-s] [-m] [-g] [-e] [-c] [-p] [-l --log_path=<path>] [--no-update-vulndb]
    {f} [-d --category=<category> --vendor=<vendor> --package=<package>]
    {f} [-i]
    {f} -h | --help
options:
    -s   Optional : Examine cloud service.
    -m   Optional : Analyze HTTP response for identify product/version using Machine Learning.
    -g   Optional : Google Custom Search for identify product/version.
    -e   Optional : Explore default path of product.
    -c   Optional : Discover open ports and wrong ssl server certification using Censys.
    -p   Optional : Execute exploit module using Metasploit.
    -l   Optional : Analyze log based HTTP response for identify product/version.
    -d   Optional : Development of signature and train data.
    -i   Optional : Explore relevant FQDN with the target FQDN. 
    -h --help     Show this help message and exit.
""".format(f=__file__)

# main.
if __name__ == '__main__':
    file_name = os.path.basename(__file__)
    full_path = os.path.dirname(os.path.abspath(__file__))

    utility = Utilty()
    utility.write_log(20, '[In] GyoiThon [{}].'.format(file_name))

    # Get command arguments.
    args = docopt(__doc__)
    opt_cloud = args['-s']
    opt_ml = args['-m']
    opt_gcs = args['-g']
    opt_explore = args['-e']
    opt_censys = args['-c']
    opt_exploit = args['-p']
    opt_log = args['-l']
    opt_log_path = args['--log_path']
    opt_develop = args['-d']
    opt_develop_category = args['--category']
    opt_develop_vendor = args['--vendor']
    opt_develop_package = args['--package']
    opt_invent = args['-i']
    opt_no_update_vulndb = args['--no-update-vulndb']

    # Read config.ini.
    config = configparser.ConfigParser()
    config.read(os.path.join(full_path, 'config.ini'))

    # Common setting value.
    log_path = ''
    method_crawl = ''
    method_log = ''
    max_target_url = 0
    max_target_byte = 0
    clipping_regex = ''
    clipping_size = 0
    clipping_buff = 0
    clipping_mark = ''
    is_scramble = False
    try:
        log_dir = config['Common']['log_path']
        log_path = os.path.join(full_path, log_dir)
        method_crawl = config['Common']['method_crawl']
        method_log = config['Common']['method_log']
        max_target_url = int(config['Common']['max_target_url'])
        max_target_byte = int(config['Common']['max_target_byte'])
        clipping_regex = config['Common']['clipping_regex']
        clipping_size = int(config['Common']['clipping_size'])
        if clipping_size <= 0:
            clipping_size = 10000
        clipping_buff = int(config['Common']['clipping_buff'])
        if clipping_buff <= 0:
            clipping_buff = 200
        clipping_mark = config['Common']['clipping_mark']
        if int(config['Common']['scramble']) == 1:
            is_scramble = True

    except Exception as e:
        msg = 'Reading config.ini is failure : {}'.format(e)
        utility.print_exception(e, msg)
        utility.write_log(40, msg)
        utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
        exit(1)

    # Show banner.
    show_banner(utility)

    # Create signature and train data.
    if opt_develop:
        creator = Creator(utility)
        creator.extract_file_structure(opt_develop_category, opt_develop_vendor, opt_develop_package)
        print(os.path.basename(__file__) + ' finish!!')
        utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
        sys.exit(0)

    # Explore relevant FQDN with the target FQDN.
    if opt_invent:
        inventory_list_path = os.path.join(full_path, 'inventory_list.txt')
        if os.path.exists(inventory_list_path):
            inventory = Inventory(utility)
            spider = SpiderControl(utility)
            google_hack = GoogleCustomSearch(utility)
            report = CreateReport(utility)

            with codecs.open(inventory_list_path, 'r', 'utf-8') as fin:
                targets = fin.readlines()
                for target in targets:
                    items = target.replace('\r', '').replace('\n', '').split('\t')
                    if len(items) != 2:
                        utility.print_message(FAIL, 'Invalid inventory target : {}'.format(target))
                        continue

                    # Check target URL.
                    port_num = ''
                    invent_url = ''
                    keyword = ''
                    try:
                        invent_url = items[0]
                        keyword = items[1]
                        parsed = util.parse_url(invent_url)

                        # Judge port number.
                        if parsed.port is None and parsed.scheme == 'https':
                            port_num = '443'
                        elif parsed.port is None and parsed.scheme == 'http':
                            port_num = '80'
                        elif parsed.port is not None:
                            port_num = str(parsed.port)
                        else:
                            utility.print_message(FAIL, 'Invalid URL : {}'.format(invent_url))
                            utility.write_log(30, 'Invalid URL : {}'.format(invent_url))
                            continue
                    except Exception as e:
                        utility.print_exception(e, 'Parsed error : {}'.format(invent_url))
                        utility.write_log(30, 'Parsed error : {}'.format(invent_url))
                        continue

                    # Check target URL.
                    if utility.check_arg_value(parsed.scheme, parsed.hostname, port_num, parsed.path) is False:
                        continue

                    # Gather relevant FQDN.
                    fqdn_list = inventory.fqdn_explore(spider, google_hack, invent_url, keyword)

                    # Create report.
                    date = utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                    print_date = utility.transform_date_string(utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))
                    report = CreateReport(utility)
                    report.create_inventory_report(fqdn_list, keyword, parsed.hostname, print_date)

                # Create merged report.
                report.create_all_inventory_report()
        else:
            utility.print_message(FAIL, '"inventory_list.txt" is not found : {}'.format(inventory_list_path))
        exit(0)

    # Create instances.
    cloud_checker = CloudChecker(utility)
    version_checker = VersionChecker(utility)
    version_checker_ml = VersionCheckerML(utility)
    comment_checker = CommentChecker(utility)
    error_checker = ErrorChecker(utility)
    page_checker = PageChecker(utility)
    google_hack = GoogleCustomSearch(utility)
    content_explorer = ContentExplorer(utility)
    spider = SpiderControl(utility)
    report = CreateReport(utility)
    cve_explorer = CveExplorerNVD(utility, opt_no_update_vulndb)
    censys = Censys(utility)

    # Get target information from "host.txt".
    protocol_list, fqdn_list, port_list, path_list = get_target_info(full_path, utility)

    # Start investigation.
    for idx in range(len(fqdn_list)):
        # Check parameters.
        utility.target_host = fqdn_list[idx]
        msg = 'investigation : {}, {}, {}, {}'.format(protocol_list[idx],
                                                      fqdn_list[idx],
                                                      port_list[idx],
                                                      path_list[idx])
        utility.write_log(20, 'Start ' + msg)
        if utility.check_arg_value(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx]) is False:
            msg = 'Invalid parameter : {}, {}, {}, {}'.format(protocol_list[idx], fqdn_list[idx],
                                                              port_list[idx], path_list[idx])
            utility.print_message(FAIL, msg)
            utility.write_log(30, msg)
            continue

        # Create report header.
        report.create_report_header(fqdn_list[idx], port_list[idx])

        # Check cloud service.
        cloud_type = 'Unknown'
        if opt_cloud:
            cloud_type = cloud_checker.get_cloud_service(fqdn_list[idx])

        # Search Censys.
        if opt_censys:
            date = utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
            print_date = utility.transform_date_string(utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))
            server_info,  cert_info = censys.search_censys(utility.forward_lookup(fqdn_list[idx]), fqdn_list[idx])
            report.create_censys_report(fqdn_list[idx],
                                        port_list[idx],
                                        server_info,
                                        cert_info,
                                        print_date)

        # Analysis HTTP responses.
        product_list = []
        if opt_log:
            # Check stored logs.
            if os.path.exists(opt_log_path) is False:
                utility.print_message(FAIL, 'Path not found: {}'.format(opt_log_path))
                utility.write_log(30, 'Path not found : {}'.format(opt_log_path))
                utility.write_log(20, '[Out] Analyze log [{}].'.format(os.path.basename(__file__)))
            else:
                log_list = glob.glob(os.path.join(opt_log_path, '*.log'))
                for log_idx, path in enumerate(log_list):
                    try:
                        target_logs = []

                        # Clipping log.
                        if max_target_byte > 0:
                            utility.print_message(WARNING, 'Cutting response byte {} to {}.'
                                                  .format(os.path.getsize(path), max_target_byte))
                            with codecs.open(path, 'r', 'utf-8') as fin:
                                try:
                                    target_logs.append(['No identification', [fin.read(max_target_byte)]])
                                except Exception as e:
                                    utility.print_exception(e, 'Skip this log : {}'.format(path))
                                    continue
                        # Dividing log.
                        else:
                            # Dividing trigger string.
                            if clipping_regex != '':
                                with codecs.open(path, 'r', 'utf-8') as fin:
                                    try:
                                        utility.print_message(WARNING, 'Dividing log per trigger string.')
                                        target_log = fin.read()
                                        tmp_logs = re.split(clipping_regex, target_log)

                                        # Dividing byte size.
                                        for tmp_log in tmp_logs:
                                            # Get target identification.
                                            target_id = 'No identification'
                                            results = re.findall(clipping_mark, tmp_log)
                                            if len(results) > 0:
                                                target_id = results[0]

                                            # Divide log.
                                            divided_logs = []
                                            divided_logs.extend(divide_data_size(tmp_log, clipping_size, clipping_buff))
                                            target_logs.append([target_id, divided_logs])
                                    except Exception as e:
                                        # Dividing byte size.
                                        utility.print_exception(e, 'Dividing log per clipping size.')
                                        divided_logs = []
                                        divided_logs.extend(divide_log_size(path, clipping_size, clipping_buff))
                                        target_logs.append(['No identification', divided_logs])
                            else:
                                # Dividing byte size.
                                divided_logs = []
                                utility.print_message(WARNING, 'Dividing log per clipping size.')
                                divided_logs.extend(divide_log_size(path, clipping_size, clipping_buff))
                                target_logs.append(['No identification', divided_logs])

                        # Analyze gathered logs.
                        for target_item in target_logs:
                            target_id = target_item[0]
                            for log_idx2, target_log in enumerate(target_item[1]):
                                date = utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                                print_date = utility.transform_date_string(
                                    utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))

                                msg = '{}/{}-{}/{} Checking : Log: {}'.format(log_idx + 1, len(log_list),
                                                                              log_idx2 + 1, len(target_logs),
                                                                              path)
                                utility.print_message(OK, msg)
                                utility.write_log(20, msg)

                                # Check product name/version using signature.
                                product_list = version_checker.get_product_name(target_log)

                                # Check product name/version using Machine Learning.
                                if opt_ml:
                                    product_list.extend(version_checker_ml.get_product_name(target_log))

                                # Get CVE for products.
                                product_list = cve_explorer.cve_explorer(product_list)

                                # Check unnecessary comments.
                                comments, comment_list = comment_checker.get_bad_comment(target_log)

                                # Save all gotten comments to the local file.
                                boundary = '-' * 5 + '[' + path + ']' + '-' * 5 + '\n' + date + '\n'
                                comment_log_name = 'all_comments.log'
                                comment_log_path = os.path.join(opt_log_path, comment_log_name)
                                with codecs.open(comment_log_path, 'a', 'utf-8') as fout:
                                    fout.write(boundary)
                                    for comment in comment_list:
                                        fout.write(comment + '\n')

                                # Check unnecessary error messages.
                                errors = error_checker.get_error_message(target_log)

                                # Create report.
                                report.create_report_body(target_id,
                                                          fqdn_list[idx],
                                                          port_list[idx],
                                                          cloud_type,
                                                          method_log,
                                                          product_list,
                                                          {},
                                                          comments,
                                                          errors,
                                                          '-',
                                                          path,
                                                          print_date)
                    except Exception as e:
                        utility.print_exception(e, 'Could not read the log : {}'.format(path))
                        utility.write_log(30, 'Could not read the log : {}'.format(path))
        else:
            # Check encoding.
            test_url = ''
            if int(port_list[idx]) in [80, 443]:
                test_url = protocol_list[idx] + '://' + fqdn_list[idx] + path_list[idx]
            else:
                test_url = protocol_list[idx] + '://' + fqdn_list[idx] + ':' + port_list[idx] + path_list[idx]
            _, server_header, res_header, res_body, encoding = utility.send_request('GET', test_url)

            # Gather target url using Spider.
            spider.utility.encoding = encoding
            web_target_info, _ = spider.run_spider(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx])

            # Add favicon.ico to target list.
            web_target_info[0][2].insert(0, protocol_list[idx] + '://' + fqdn_list[idx] + '/favicon.ico')

            # Get HTTP responses.
            for target in web_target_info:
                # Scramble and Cutting loop count.
                target_list = target[2]
                if is_scramble is True:
                    utility.print_message(WARNING, 'Scramble target list.')
                    target_list = random.sample(target[2], len(target[2]))
                if max_target_url != 0 and max_target_url < len(target_list):
                    utility.print_message(WARNING, 'Cutting target list {} to {}.'.format(len(target[2]),
                                                                                          max_target_url))
                    target_list = target_list[:max_target_url]

                for count, target_url in enumerate(target_list):
                    target_datas = []
                    utility.print_message(NOTE, '{}/{} Start analyzing: {}'.format(count+1,
                                                                                   len(target_list),
                                                                                   target_url))

                    # Check target url.
                    parsed = None
                    try:
                        parsed = util.parse_url(target_url)
                    except Exception as e:
                        utility.print_exception(e, 'Parsed error : {}'.format(target_url))
                        utility.write_log(30, 'Parsed error : {}'.format(target_url))
                        continue

                    # Get HTTP response (header + body).
                    date = utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                    print_date = utility.transform_date_string(utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))
                    _, server_header, res_header, res_body, _ = utility.send_request('GET', target_url)

                    # Write log.
                    log_name = protocol_list[idx] + '_' + fqdn_list[idx] + '_' + str(port_list[idx]) + '_' + date + '.log'
                    log_path_fqdn = os.path.join(log_path, fqdn_list[idx] + '_' + str(port_list[idx]))
                    if os.path.exists(log_path_fqdn) is False:
                        os.mkdir(log_path_fqdn)
                    log_file = os.path.join(log_path_fqdn, log_name)
                    with codecs.open(log_file, 'w', 'utf-8') as fout:
                        fout.write(target_url + '\n\n' + res_header + '\n\n' + res_body)

                    # Cutting response byte.
                    if max_target_byte > 0:
                        utility.print_message(WARNING, 'Cutting response byte {} to {}.'.format(len(res_body),
                                                                                                max_target_byte))
                        target_datas.append(res_body[:max_target_byte])
                    else:
                        # Divide response byte.
                        target_datas.extend(divide_data_size(res_body, clipping_size, clipping_buff))
                        utility.print_message(WARNING, 'Divided response byte to {}.'.format(len(target_datas)))

                    for data_idx, target_data in enumerate(target_datas):
                        msg = '{}/{} Checking : divided data: {}'.format(data_idx + 1, len(target_datas), target_url)
                        utility.print_message(OK, msg)

                        if data_idx == 0:
                            target_data = res_header + target_data

                        # Check product name/version using signature.
                        product_list = version_checker.get_product_name(target_data)

                        # Check product name/version using Machine Learning.
                        if opt_ml:
                            product_list.extend(version_checker_ml.get_product_name(target_data))

                        # Get CVE for products.
                        product_list = cve_explorer.cve_explorer(product_list)

                        # Check unnecessary comments.
                        comments, comment_list = comment_checker.get_bad_comment(target_data)

                        # Save all gotten comments to the local file.
                        boundary = '-' * 5 + '[' + target_url + ']' + '-' * 5 + '\n' + date + '\n'
                        comment_log_name = 'all_comments.log'
                        comment_log_path = os.path.join(log_path_fqdn, comment_log_name)
                        with codecs.open(comment_log_path, 'a', 'utf-8') as fout:
                            fout.write(boundary)
                            for comment in comment_list:
                                fout.write(comment + '\n')

                        # Check unnecessary error messages.
                        errors = error_checker.get_error_message(target_data)

                        # Check login page.
                        page_type = page_checker.judge_page_type(target_url, target_data)

                        # Create report.
                        report.create_report_body(target_url,
                                                  fqdn_list[idx],
                                                  port_list[idx],
                                                  cloud_type,
                                                  method_crawl,
                                                  product_list,
                                                  page_type,
                                                  comments,
                                                  errors,
                                                  server_header,
                                                  log_file,
                                                  print_date,
                                                  test_url)

        # Check unnecessary contents using Google Hack.
        if opt_gcs:
            product_list = google_hack.execute_google_hack(cve_explorer,
                                                           fqdn_list[idx],
                                                           port_list[idx],
                                                           report,
                                                           max_target_byte)

        # Check unnecessary contents using Explore contents.
        if opt_explore:
            product_list.extend(content_explorer.content_explorer(cve_explorer,
                                                                  protocol_list[idx],
                                                                  fqdn_list[idx],
                                                                  port_list[idx],
                                                                  path_list[idx],
                                                                  report,
                                                                  max_target_byte))

        # Execute exploitation.
        if opt_exploit:
            exploit = Exploit(utility)
            exploit_product = list(map(list, set(map(tuple, [[products[1], products[2]] for products in product_list]))))
            exploit.exploit({'fqdn': fqdn_list[idx],
                             'ip': utility.forward_lookup(fqdn_list[idx]),
                             'port': int(port_list[idx]),
                             'prod_list': exploit_product,
                             'path': path_list[idx].replace('/', '')})

            # Create exploiting report.
            report.create_exploit_report(fqdn_list[idx], port_list[idx])

        utility.write_log(20, 'End ' + msg)

    print(os.path.basename(__file__) + ' finish!!')
    utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
