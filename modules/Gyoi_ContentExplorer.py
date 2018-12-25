#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import re
import time
import configparser

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class ContentExplorer:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.signature_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.method_name = config['Common']['method_direct']
            self.signature_file = config['ContentExplorer']['signature_file']
            self.delay_time = float(config['ContentExplorer']['delay_time'])
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Check product version.
    def check_version(self, default_ver, version_pattern, response):
        # Check version.
        version = default_ver
        if version_pattern != '*':
            obj_match = re.search(version_pattern, response, flags=re.IGNORECASE)
            if obj_match is not None and obj_match.re.groups > 1:
                version = obj_match.group(2)
        return version

    # Examine HTTP response.
    def examine_response(self, check_pattern, default_ver, version_pattern, response):
        self.utility.print_message(NOTE, 'Confirm string matching.')
        self.utility.write_log(20, '[In] Confirm string matching [{}].'.format(self.file_name))

        # Check exsisting contents.
        result = []
        if check_pattern != '*' and re.search(check_pattern, response, flags=re.IGNORECASE) is not None:
            result.append(True)
            # Check product version.
            result.append(self.check_version(default_ver, version_pattern, response))
        elif check_pattern == '*':
            result.append(True)
            # Check product version.
            result.append(self.check_version(default_ver, version_pattern, response))
        else:
            result.append(False)
            result.append(default_ver)
        return result

    # Explore unnecessary contents.
    def content_explorer(self, cve_explorer, protocol, fqdn, port, path, report, max_target_byte):
        self.utility.print_message(NOTE, 'Explore unnecessary contents.')
        self.utility.write_log(20, '[In] Explore contents [{}].'.format(self.file_name))

        # Open signature file.
        target_base = protocol + '://' + fqdn + ':' + str(port) + path
        signature_file = os.path.join(self.signature_dir, self.signature_file)
        product_list = []
        with codecs.open(signature_file, 'r', encoding='utf-8') as fin:
            signatures = fin.readlines()
            for idx, signature in enumerate(signatures):
                items = signature.replace('\n', '').replace('\r', '').split('@')
                category = items[0]
                vendor = items[1].lower()
                product_name = items[2].lower()
                default_ver = items[3]
                path = items[4]
                check_pattern = items[5]
                version_pattern = items[6]
                is_login = items[7]
                target_url = ''
                if path.startswith('/') is True:
                    target_url = target_base + path[1:]
                else:
                    target_url = target_base + path[4]

                # Get HTTP response (header + body).
                date = self.utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                print_date = self.utility.transform_date_string(
                    self.utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))
                res, server_header, res_header, res_body, _ = self.utility.send_request('GET', target_url)
                msg = '{}/{} Accessing : Status: {}, Url: {}'.format(idx + 1, len(signatures), res.status, target_url)
                self.utility.print_message(OK, msg)
                self.utility.write_log(20, msg)

                # Write log.
                log_name = protocol + '_' + fqdn + '_' + str(port) + '_' + date + '.log'
                log_path_fqdn = os.path.join(os.path.join(self.root_path, 'logs'), fqdn + '_' + str(port))
                if os.path.exists(log_path_fqdn) is False:
                    os.mkdir(log_path_fqdn)
                log_file = os.path.join(log_path_fqdn, log_name)
                with codecs.open(log_file, 'w', 'utf-8') as fout:
                    fout.write(target_url + '\n\n' + res_header + '\n\n' + res_body)

                if res.status in [200, 301, 302]:
                    # Cutting response byte.
                    if max_target_byte != 0 and (max_target_byte < len(res_body)):
                        self.utility.print_message(WARNING, 'Cutting response byte {} to {}.'
                                                   .format(len(res_body), max_target_byte))
                        res_body = res_body[:max_target_byte]

                    # Examine HTTP response.
                    result = self.examine_response(check_pattern,
                                                   default_ver,
                                                   version_pattern,
                                                   res_header + '\n\n' + res_body)
                    if result[0] is True:
                        # Found unnecessary content or CMS admin page.
                        product = [category, vendor, product_name, result[1], path]
                        product = cve_explorer.cve_explorer([product])
                        product_list.extend(product)
                        msg = 'Find product={}/{}, verson={}, trigger={}'.format(vendor, product_name, default_ver, path)
                        self.utility.print_message(OK, msg)
                        self.utility.write_log(20, msg)

                        # Create report.
                        page_type = {}
                        if is_login == '1':
                            page_type = {'ml': {'prob': '-', 'reason': '-'}, 'url': {'prob': '100%', 'reason': path}}
                        report.create_report_body(target_url, fqdn, port, '*', self.method_name, product,
                                                  page_type, [], [], server_header, log_file, print_date)

                time.sleep(self.delay_time)
        self.utility.write_log(20, '[Out] Explore contents [{}].'.format(self.file_name))
        return product_list
