#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import codecs
import re
import urllib3
import configparser
from googleapiclient.discovery import build
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class GoogleCustomSearch:
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
            self.method_name = config['Common']['method_search']
            self.api_key = config['GoogleHack']['api_key']
            self.search_engine_id = config['GoogleHack']['search_engine_id']
            self.signature_file = config['GoogleHack']['signature_file']
            self.api_strict_key = config['GoogleHack']['api_strict_key']
            self.api_strict_value = config['GoogleHack']['api_strict_value']
            self.start_index = int(config['GoogleHack']['start_index'])
            self.delay_time = float(config['GoogleHack']['delay_time'])
            self.delay_time_direct_access = float(config['ContentExplorer']['delay_time'])
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

        # Check existing contents.
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

    def execute_google_hack(self, cve_explorer, fqdn, path, report):
        self.utility.print_message(NOTE, 'Execute Google hack.')
        self.utility.write_log(20, '[In] Execute Google hack [{}].'.format(self.file_name))

        # Open signature file.
        signature_file = os.path.join(self.signature_dir, self.signature_file)
        product_list = []
        with codecs.open(signature_file, 'r', encoding='utf-8') as fin:
            signatures = fin.readlines()

            # Execute Google search.
            for idx, signature in enumerate(signatures):
                items = signature.replace('\n', '').replace('\r', '').split('@')
                if len(items) != 8:
                    self.utility.print_message(WARNING, 'Invalid signature: {}'.format(signature))
                    continue
                category = items[0]
                vendor = items[1].lower()
                product_name = items[2].lower()
                default_ver = items[3]
                search_option = items[4]
                check_pattern = items[5]
                version_pattern = items[6]
                is_login = items[7]
                query = 'site:' + fqdn + ' ' + search_option
                date = self.utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                print_date = self.utility.transform_date_string(
                    self.utility.transform_date_object(date[:-3], '%Y%m%d%H%M%S'))

                # Execute.
                urls, result_count = self.custom_search(query, self.start_index)

                msg = '{}/{} Execute query: {}'.format(idx + 1, len(signature), query)
                self.utility.print_message(OK, msg)
                self.utility.write_log(20, msg)

                if result_count != 0:
                    if check_pattern != '*' or version_pattern != '*':
                        for url_idx, target_url in enumerate(urls):
                            # Get HTTP response (header + body).
                            date = self.utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                            res, server_header, res_header, res_body = self.utility.send_request('GET', target_url)
                            msg = '{}/{} Accessing : Status: {}, Url: {}'.format(url_idx + 1,
                                                                                 len(urls),
                                                                                 res.status,
                                                                                 target_url)
                            self.utility.print_message(OK, msg)
                            self.utility.write_log(20, msg)

                            # Write log.
                            log_name = 'google_custom_search_' + fqdn + '_' + date + '.log'
                            log_path_fqdn = os.path.join(os.path.join(self.root_path, 'logs'),
                                                         fqdn + '_' + path.replace('/', ''))
                            if os.path.exists(log_path_fqdn) is False:
                                os.mkdir(log_path_fqdn)
                            log_file = os.path.join(log_path_fqdn, log_name)
                            with codecs.open(log_file, 'w', 'utf-8') as fout:
                                fout.write(target_url + '\n\n' + res_header + res_body)

                            # Examine HTTP response.
                            result = self.examine_response(check_pattern,
                                                           default_ver,
                                                           version_pattern,
                                                           res_header + res_body)

                            if result[0] is True:
                                # Found unnecessary content or CMS admin page.
                                product = [category, vendor, product_name, result[1], target_url]
                                product = cve_explorer.cve_explorer([product])
                                product_list.extend(product)
                                msg = 'Find product={}/{}, verson={}, trigger={}'.format(vendor, product_name,
                                                                                         default_ver, target_url)
                                self.utility.print_message(OK, msg)
                                self.utility.write_log(20, msg)

                                # Create report.
                                page_type = {}
                                if is_login == '1':
                                    page_type = {'ml': {'prob': '-', 'reason': '-'},
                                                 'url': {'prob': '100%', 'reason': target_url}}
                                report.create_report_body(target_url, fqdn, path, target_url, '*', self.method_name,
                                                          product, page_type, [], [], server_header, log_file, print_date)

                            time.sleep(self.delay_time_direct_access)
                    else:
                        # Found search result.
                        product = [category, vendor, product_name, default_ver, query]
                        product = cve_explorer.cve_explorer([product])
                        product_list.append(product)
                        msg = 'Detected default content: {}/{}'.format(vendor, product_name)
                        self.utility.print_message(OK, msg)
                        self.utility.write_log(20, msg)

                        page_type = {}
                        if is_login == 1:
                            page_type = {'ml': {'prob': '-', 'reason': '-'},
                                         'url': {'prob': '100%', 'reason': search_option}}
                        report.create_report_body('-', fqdn, '*', '*', self.method_name, product, page_type,
                                                  [], [], '*', '*', print_date)

                time.sleep(self.delay_time)
        self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
        return product_list

    # APIのアクセスはIPで制限
    # 制限の設定はGCP consoleで実施。
    def custom_search(self, query, start_index=1):
        # Google Custom Search API.
        self.utility.write_log(20, '[In] Execute Google custom search [{}].'.format(self.file_name))

        # Setting of Google Custom Search.
        service = build("customsearch", "v1", developerKey=self.api_key)
        response = []
        urls = []
        result_count = 0

        # Execute search.
        try:
            response.append(service.cse().list(
                q=query,
                cx=self.search_engine_id,
                num=10,
                start=self.start_index
            ).execute())

            # Get finding counts.
            result_count = int(response[0].get('searchInformation').get('totalResults'))

            # Get extracted link (url).
            if result_count != 0:
                items = response[0]['items']
                for item in items:
                    urls.append(item['link'])

        except Exception as e:
            msg = 'Google custom search is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)
            self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
            return urls, result_count

        self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
        return urls, result_count
