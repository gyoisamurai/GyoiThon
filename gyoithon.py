#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import codecs
import time
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
    utility.write_log(20, '[In] Get target information [{}].'.format(os.path.basename(__file__)))
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

    utility.write_log(20, '[Out] Get target information [{}].'.format(os.path.basename(__file__)))
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
       =[ GyoiThon v0.0.2-beta                               ]=
+ -- --=[ Author  : Gyoiler (@gyoithon)                      ]=--
+ -- --=[ Website : https://github.com/gyoisamurai/GyoiThon/ ]=--
    """
    utility.print_message(NONE, credit)


# Define command option.
__doc__ = """{f}
usage:
    {f} [-m] [-g] [-e] [-c] [-p] [-l <log_path>]
    {f} -h | --help
options:
    -m   Optional : Analyze HTTP response for identify product/version using Machine Learning.
    -g   Optional : Google Custom Search for identify product/version.
    -e   Optional : Explore default path of product.
    -c   Optional : Discover open ports and wrong ssl server certification using Censys.
    -p   Optional : Execute exploit module using Metasploit.
    -l   Optional : Analyze log based HTTP response for identify product/version.
    -h --help     Show this help message and exit.
""".format(f=__file__)


# Parse command arguments.
def command_parse(utility):
    utility.write_log(20, '[In] Parse command options [{}].'.format(os.path.basename(__file__)))

    args = docopt(__doc__)
    opt_ml = args['-m']
    opt_gcs = args['-g']
    opt_explore = args['-e']
    opt_censys = args['-c']
    opt_exploit = args['-p']
    opt_log = args['-l']
    opt_log_path = args['<log_path>']

    utility.write_log(20, '[Out] Parse command options [{}].'.format(os.path.basename(__file__)))
    return opt_ml, opt_gcs, opt_explore, opt_censys, opt_exploit, opt_log, opt_log_path


# main.
if __name__ == '__main__':
    file_name = os.path.basename(__file__)
    full_path = os.path.dirname(os.path.abspath(__file__))

    utility = Utilty()
    utility.write_log(20, '[In] GyoiThon [{}].'.format(file_name))

    # Get command arguments.
    opt_ml, opt_gcs, opt_explore, opt_censys, opt_exploit, opt_log, opt_log_path = command_parse(utility)

    # Read config.ini.
    config = configparser.ConfigParser()
    config.read(os.path.join(full_path, 'config.ini'))

    # Common setting value.
    log_path = ''
    method_crawl = ''
    method_log = ''
    try:
        log_dir = config['Common']['log_path']
        log_path = os.path.join(full_path, log_dir)
        method_crawl = config['Common']['method_crawl']
        method_log = config['Common']['method_log']
    except Exception as e:
        msg = 'Reading config.ini is failure : {}'.format(e)
        utility.print_exception(e, msg)
        utility.write_log(40, msg)
        utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
        exit(1)

    # Show banner.
    show_banner(utility)

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
    cve_explorer = CveExplorerNVD(utility)
    censys = Censys(utility)

    # Get target information from "host.txt".
    protocol_list, fqdn_list, port_list, path_list = get_target_info(full_path, utility)

    # Start investigation.
    for idx in range(len(fqdn_list)):
        # Check parameters.
        msg = 'investigation : {}, {}, {}, {}'.format(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx])
        utility.write_log(20, 'Start ' + msg)
        if utility.check_arg_value(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx]) is False:
            msg = 'Invalid parameter : {}, {}, {}, {}'.format(protocol_list[idx], fqdn_list[idx],
                                                              port_list[idx], path_list[idx])
            utility.print_message(FAIL, msg)
            utility.write_log(30, msg)
            continue

        # Create report header.
        report.create_report_header(fqdn_list[idx], path_list[idx].replace('/', ''))

        # Check cloud service.
        cloud_type = cloud_checker.get_cloud_service(fqdn_list[idx])

        # Search Censys.
        if opt_censys:
            censys.search_censys(protocol_list[idx], utility.forward_lookup(fqdn_list[idx]), fqdn_list[idx])

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
                        with codecs.open(path, 'r', 'utf-8') as fin:
                            target_log = fin.read()
                            date = utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                            print_date = utility.transform_date_string(
                                utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))

                            msg = '{}/{} Checking : Log: {}'.format(log_idx + 1, len(log_list), path)
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
                            comments = comment_checker.get_bad_comment(target_log)

                            # Check unnecessary error messages.
                            errors = error_checker.get_error_message(target_log)

                            # Create report.
                            report.create_report_body('-',
                                                      fqdn_list[idx],
                                                      path_list[idx].replace('/', ''),
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
                        utility.print_exception(e, 'Not read log : {}'.format(path))
                        utility.write_log(30, 'Not read log : {}'.format(path))
        else:
            # Gather target url using Spider.
            web_target_info = spider.run_spider(protocol_list[idx], fqdn_list[idx], port_list[idx], path_list[idx])

            # Get HTTP responses.
            for target in web_target_info:
                for count, target_url in enumerate(target[2]):
                    utility.print_message(NOTE, '{}/{} Start analyzing: {}'.format(count+1, len(target[2]), target_url))

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
                    _, server_header, res_header, res_body = utility.send_request('GET', target_url)

                    # Write log.
                    log_name = protocol_list[idx] + '_' + fqdn_list[idx] + '_' + str(port_list[idx]) + '_' + date + '.log'
                    log_path_fqdn = os.path.join(log_path, fqdn_list[idx] + '_' + path_list[idx].replace('/', ''))
                    if os.path.exists(log_path_fqdn) is False:
                        os.mkdir(log_path_fqdn)
                    log_file = os.path.join(log_path_fqdn, log_name)
                    with codecs.open(log_file, 'w', 'utf-8') as fout:
                        fout.write(target_url + '\n\n' + res_header + res_body)

                    # Check product name/version using signature.
                    product_list = version_checker.get_product_name(res_header + res_body)

                    # Check product name/version using Machine Learning.
                    if opt_ml:
                        product_list.extend(version_checker_ml.get_product_name(res_header + res_body))

                    # Get CVE for products.
                    product_list = cve_explorer.cve_explorer(product_list)

                    # Check unnecessary comments.
                    comments = comment_checker.get_bad_comment(res_body)

                    # Check unnecessary error messages.
                    errors = error_checker.get_error_message(res_body)

                    # Check login page.
                    page_type = page_checker.judge_page_type(target_url, res_body)

                    # Create report.
                    report.create_report_body(target_url,
                                              fqdn_list[idx],
                                              path_list[idx].replace('/', ''),
                                              port_list[idx],
                                              cloud_type,
                                              method_crawl,
                                              product_list,
                                              page_type,
                                              comments,
                                              errors,
                                              server_header,
                                              log_file,
                                              print_date)

        # Check unnecessary contents using Google Hack.
        if opt_gcs:
            product_list = google_hack.execute_google_hack(cve_explorer,
                                                           fqdn_list[idx],
                                                           path_list[idx].replace('/', ''),
                                                           report)

        # Check unnecessary contents using Explore contents.
        if opt_explore:
            product_list.extend(content_explorer.content_explorer(cve_explorer,
                                                                  protocol_list[idx],
                                                                  fqdn_list[idx],
                                                                  path_list[idx].replace('/', ''),
                                                                  port_list[idx],
                                                                  path_list[idx],
                                                                  report))

        # Execute exploitation.
        if opt_exploit:
            exploit = Exploit(utility)
            exploit_product = list(map(list, set(map(tuple, [[products[1], products[2]] for products in product_list]))))
            exploit.exploit({'ip': utility.forward_lookup(fqdn_list[idx]),
                             'port': int(port_list[idx]),
                             'prod_list': exploit_product})

            # Create exploiting report.
            report.create_exploit_report()

        utility.write_log(20, 'End ' + msg)

    print(os.path.basename(__file__) + ' finish!!')
    utility.write_log(20, '[Out] GyoiThon [{}].'.format(file_name))
