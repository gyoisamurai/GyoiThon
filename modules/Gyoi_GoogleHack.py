#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import codecs
import re
import configparser
import httplib2
import socks
from urllib3 import util
from googleapiclient.discovery import build

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
            self.action_name = 'Google Hacking'
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

    def execute_google_hack(self, cve_explorer, fqdn, port, report, max_target_byte):
        self.utility.print_message(NOTE, 'Execute Google hack.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Execute Google hack',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

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
                urls, result_count, _ = self.custom_search(query)

                msg = '{}/{} Execute query: {}'.format(idx + 1, len(signatures), query)
                self.utility.print_message(OK, msg)
                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note=msg,
                                                dest=self.utility.target_host)
                self.utility.write_log(20, msg)

                if result_count != 0:
                    if check_pattern != '*' or version_pattern != '*':
                        for url_idx, target_url in enumerate(urls):
                            # Get HTTP response (header + body).
                            date = self.utility.get_current_date('%Y%m%d%H%M%S%f')[:-3]
                            res, server_header, res_header, res_body, _ = self.utility.send_request('GET', target_url)
                            msg = '{}/{} Accessing : Status: {}, Url: {}'.format(url_idx + 1,
                                                                                 len(urls),
                                                                                 res.status,
                                                                                 target_url)
                            self.utility.print_message(OK, msg)
                            self.utility.write_log(20, msg)

                            # Write log.
                            log_name = 'google_custom_search_' + fqdn + '_' + str(port) + '_' + date + '.log'
                            log_path_fqdn = os.path.join(os.path.join(self.root_path, 'logs'), fqdn + '_' + str(port))
                            if os.path.exists(log_path_fqdn) is False:
                                os.mkdir(log_path_fqdn)
                            log_file = os.path.join(log_path_fqdn, log_name)
                            with codecs.open(log_file, 'w', 'utf-8') as fout:
                                fout.write(target_url + '\n\n' + res_header + '\n\n' + res_body)

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
                                product = [category, vendor, product_name, result[1], target_url]
                                product = cve_explorer.cve_explorer([product])
                                product_list.extend(product)
                                msg = 'Find product={}/{}, verson={}, trigger={}'.format(vendor, product_name,
                                                                                         default_ver, target_url)
                                self.utility.print_message(OK, msg)
                                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                                self.utility.log_dis,
                                                                self.file_name,
                                                                action=self.action_name,
                                                                note=msg,
                                                                dest=self.utility.target_host)
                                self.utility.write_log(20, msg)

                                # Create report.
                                page_type = {}
                                if is_login == '1':
                                    page_type = {'ml': {'prob': '-', 'reason': '-'},
                                                 'url': {'prob': '100%', 'reason': target_url}}
                                report.create_report_body(target_url, fqdn, port, '*', self.method_name, product,
                                                          page_type, [], [], server_header, log_file, print_date)

                            time.sleep(self.delay_time_direct_access)
                    else:
                        # Found search result.
                        product = [category, vendor, product_name, default_ver, query]
                        product = cve_explorer.cve_explorer([product])
                        product_list.append(product)
                        msg = 'Detected default content: {}/{}'.format(vendor, product_name)
                        self.utility.print_message(OK, msg)
                        msg = self.utility.make_log_msg(self.utility.log_mid,
                                                        self.utility.log_dis,
                                                        self.file_name,
                                                        action=self.action_name,
                                                        note=msg,
                                                        dest=self.utility.target_host)
                        self.utility.write_log(20, msg)

                        page_type = {}
                        if is_login == 1:
                            page_type = {'ml': {'prob': '-', 'reason': '-'},
                                         'url': {'prob': '100%', 'reason': search_option}}
                        report.create_report_body('-', fqdn, port, '*', self.method_name, product,
                                                  page_type, [], [], '*', '*', print_date, '-')

                time.sleep(self.delay_time)

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Execute Google hack',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return product_list

    # Search domain.
    def search_domain(self, target_domain, max_search_num):
        self.utility.print_message(NOTE, 'Execute Domain Search.')
        self.utility.write_log(20, '[In] Execute Domain Search [{}].'.format(self.file_name))

        # Execute.
        query = 'site:' + target_domain
        _, _, fqdn_list = self.custom_search(query, max_page_count=max_search_num, target_fqdn=target_domain)
        if len(fqdn_list) != 0:
            self.utility.print_message(OK, 'Gathered FQDN : {}'.format(fqdn_list))

        self.utility.write_log(20, '[Out] Execute Domain Search [{}].'.format(self.file_name))
        return fqdn_list

    # Search relevant FQDN.
    def search_relevant_fqdn(self, target_fqdn, search_fqdn):
        self.utility.print_message(NOTE, 'Execute relevant FQDN Search.')
        self.utility.write_log(20, '[In] Execute relevant FQDN Search [{}].'.format(self.file_name))

        # Execute.
        is_relevant = False
        query = 'link:' + target_fqdn + ' site:' + search_fqdn
        _, result_count, _ = self.custom_search(query)

        # Check result.
        if result_count != 0:
            is_relevant = True

        self.utility.write_log(20, '[Out] Execute relevant FQDN Search [{}].'.format(self.file_name))
        return is_relevant

    # Search relevant FQDN.
    def search_related_fqdn(self, target_fqdn, keyword, max_search_num):
        self.utility.print_message(NOTE, 'Execute related FQDN Search.')
        self.utility.write_log(20, '[In] Execute related FQDN Search [{}].'.format(self.file_name))

        # Execute.
        query = 'related:' + keyword + ' link:' + target_fqdn + ' -site:' + target_fqdn
        _, _, fqdn_list = self.custom_search(query, max_page_count=max_search_num)

        self.utility.write_log(20, '[Out] Execute relevant FQDN Search [{}].'.format(self.file_name))
        return fqdn_list

    # Execute Google custom search.
    def custom_search(self, query, max_page_count=1, target_fqdn=''):
        # Google Custom Search API.
        self.utility.write_log(20, '[In] Execute Google custom search [{}].'.format(self.file_name))

        # Setting of Google Custom Search.
        service = None
        if self.utility.proxy != '':
            # Set proxy.
            self.utility.print_message(WARNING, 'Set proxy server: {}'.format(self.utility.proxy))
            parsed = util.parse_url(self.utility.proxy)
            proxy = None
            if self.utility.proxy_pass != '':
                proxy = httplib2.ProxyInfo(proxy_type=socks.PROXY_TYPE_HTTP,
                                           proxy_host=parsed.host,
                                           proxy_port=parsed.port,
                                           proxy_user=self.utility.proxy_user,
                                           proxy_pass=self.utility.proxy_pass)
            else:
                proxy = httplib2.ProxyInfo(proxy_type=socks.PROXY_TYPE_HTTP,
                                           proxy_host=parsed.host,
                                           proxy_port=parsed.port)
            my_http = httplib2.Http(proxy_info=proxy, disable_ssl_certificate_validation=True)
            service = build("customsearch", "v1", developerKey=self.api_key, http=my_http)
        else:
            # None proxy.
            service = build("customsearch", "v1", developerKey=self.api_key)

        # Execute search.
        urls = []
        fqdn_list = []
        result_count = 0
        start_index = self.start_index
        try:
            search_count = 0
            while search_count < max_page_count:
                self.utility.print_message(OK, 'Using query : {}'.format(query))
                response = service.cse().list(
                    q=query,
                    cx=self.search_engine_id,
                    num=10,
                    start=start_index,
                    filter='0',
                    safe='off',
                ).execute()

                # Get finding counts.
                result_count = int(response.get('searchInformation').get('totalResults'))
                is_new_query = False

                # Get extracted link (url).
                search_urls = []
                if result_count != 0:
                    items = response['items']
                    for item in items:
                        urls.append(item['link'])
                        search_urls.append(item['link'])

                # Set new query.
                if result_count <= 10 or max_page_count == 1:
                    fqdn_list.extend(self.utility.transform_url_hostname_list(search_urls))
                    break
                else:
                    # Refine search range using "-inurl" option.
                    tmp_list = self.utility.transform_url_hostname_list(search_urls)
                    for fqdn in tmp_list:
                        if fqdn not in fqdn_list:
                            subdomain = self.utility.extract_subdomain(fqdn, target_fqdn)
                            if target_fqdn != '' and subdomain == target_fqdn:
                                query += ' -inurl:http://' + subdomain + ' -inurl:https://' + subdomain
                                is_new_query = True
                                search_count = -1
                            elif subdomain != '':
                                query += ' -inurl:' + subdomain
                                is_new_query = True
                                search_count = -1
                            fqdn_list.append(fqdn)
                    if is_new_query is False:
                        if 'nextPage' in response.get('queries').keys():
                            start_index = response.get('queries').get('nextPage')[0].get('startIndex')
                        else:
                            self.utility.print_message(WARNING, 'There is not next page.')
                            break

                search_count += 1
        except Exception as e:
            msg = 'Google custom search is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)
            self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
            return urls, result_count, fqdn_list

        self.utility.write_log(20, '[Out] Execute Google custom search [{}].'.format(self.file_name))
        return urls, result_count, list(set(fqdn_list))
