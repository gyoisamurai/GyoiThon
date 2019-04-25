#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import time
import re
import tldextract
import subprocess
import configparser
from urllib3 import util

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class Inventory:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'), encoding='utf-8')

        try:
            self.signature_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.black_list_path = os.path.join(self.signature_dir, config['Inventory']['black_list'])
            self.black_list = []
            if os.path.exists(self.black_list_path) is False:
                self.black_list = []
            else:
                with codecs.open(self.black_list_path, 'r', encoding='utf-8') as fin:
                    self.black_list = fin.readlines()
            self.max_search_num = int(config['Inventory']['max_search_num'])
            self.jprs_url = config['Inventory']['jprs_url']
            self.jprs_post = {'type': 'DOM-HOLDER', 'key': ''}
            self.jprs_regex_multi = config['Inventory']['jprs_regex_multi']
            self.jprs_regex_single = config['Inventory']['jprs_regex_single']
            self.jpnic_url = config['Inventory']['jpnic_url']
            self.jpnic_post = {'codecheck-sjis': 'にほんねっとわーくいんふぉめーしょんせんたー',
                               'key': '', 'submit': '検索', 'type': 'NET-HOLDER', 'rule': ''}
            self.jpnic_regex_multi = config['Inventory']['jpnic_regex_multi']
            self.jpnic_regex_single = config['Inventory']['jpnic_regex_single']
            self.nslookup_delay_time = float(config['Inventory']['nslookup_delay_time'])
            self.nslookup_cmd = config['Inventory']['nslookup_cmd']
            self.nslookup_options = config['Inventory']['nslookup_options'].split('@')
            self.cname_regex = config['Inventory']['cname_regex'].split('@')
            self.mx_rec_regex = config['Inventory']['mx_rec_regex'].split('@')
            self.mx_rec_regex_multi = config['Inventory']['mx_rec_regex_multi'].split('@')
            self.ns_rec_regex = config['Inventory']['ns_rec_regex'].split('@')
            self.soa_rec_regex = config['Inventory']['soa_rec_regex'].split('@')
            self.txt_rec_regex = config['Inventory']['txt_rec_regex'].split('@')
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Check black list.
    def check_black_list(self, fqdn_list):
        for idx, fqdn in enumerate(fqdn_list):
            for exclude_fqdn in self.black_list:
                if fqdn == exclude_fqdn.replace('\n', '').replace('\r', ''):
                    del fqdn_list[idx]
                    self.utility.print_message(WARNING, '"{}" is include black list.'.format(fqdn))
        return fqdn_list

    # Explore relevant link.
    def link_explorer(self, spider, google_hack, target_url, keyword):
        self.utility.print_message(NOTE, 'Explore relevant FQDN.')
        self.utility.write_log(20, '[In] Explore relevant FQDN [{}].'.format(self.file_name))

        # Send request for checking encoding type.
        _, _, _, _, encoding = self.utility.send_request('GET', target_url)

        # Gather FQDN from link of target web site.
        spider.utility.encoding = encoding
        parsed = util.parse_url(target_url)
        port = '0'
        if parsed.port is None and parsed.scheme == 'https':
            port = '443'
        elif parsed.port is None and parsed.scheme == 'http':
            port = '80'
        _, url_list = spider.run_spider(parsed.scheme, parsed.host, port, parsed.path)
        link_fqdn_list = self.check_black_list(self.utility.transform_url_hostname_list(url_list))

        # Search FQDN that include link to the target FQDN using Google Custom Search.
        non_reverse_link_fqdn = []
        for del_idx, search_fqdn in enumerate(link_fqdn_list):
            # Check reverse link to target FQDN.
            if google_hack.search_relevant_fqdn(parsed.host, search_fqdn) is False:
                non_reverse_link_fqdn.append(link_fqdn_list[del_idx])
                del link_fqdn_list[del_idx]

        # Search related FQDN using Google Custom Search.
        searched_list = []
        searched_list.extend(google_hack.search_related_fqdn(parsed.host, keyword, self.max_search_num))
        related_fqdn_list = self.check_black_list(searched_list)

        self.utility.write_log(20, '[Out] Explore relevant FQDN [{}].'.format(self.file_name))
        return list(set(link_fqdn_list.extend(related_fqdn_list))), list(set(non_reverse_link_fqdn))

    # Explore FQDN using JPRS.
    def jprs_fqdn_explore(self, google_hack, keyword):
        self.utility.print_message(NOTE, 'Explore FQDN using JPRS.')
        self.utility.write_log(20, '[In] Explore FQDN using JPRS [{}].'.format(self.file_name))

        # Send request for gathering domain.
        domain_list = []
        self.jprs_post['key'] = keyword
        res, _, _, res_body, _ = self.utility.send_request('POST',
                                                           self.jprs_url,
                                                           body_param=self.jprs_post)
        if res.status == 200:
            domain_list = re.findall(self.jprs_regex_multi.format(keyword), res_body)
            if len(domain_list) == 0:
                domain_list = re.findall(self.jprs_regex_single.format(keyword), res_body)
                if len(domain_list) != 0:
                    self.utility.print_message(NOTE, 'Gathered domain from JPRS. : {}'.format(domain_list))
                else:
                    self.utility.print_message(WARNING, 'Could not gather domain from JPRS.')
            else:
                self.utility.print_message(NOTE, 'Gathered domain from JPRS. : {}'.format(domain_list))

        # Explore FQDN using gathered domain list.
        fqdn_list = []
        for domain in list(set(domain_list)):
            fqdn_list.extend(google_hack.search_domain(domain.lower(), self.max_search_num))

        # Extract FQDN.
        fqdn_list = list(set(fqdn_list))
        jprs_fqdn_list = self.check_black_list(fqdn_list)

        self.utility.write_log(20, '[Out] Explore FQDN using JPRS [{}].'.format(self.file_name))
        return jprs_fqdn_list

    # Explore FQDN using JPRS.
    def mutated_fqdn_explore(self, google_hack, origin_fqdn_list):
        self.utility.print_message(NOTE, 'Explore mutated FQDN using Google Hack.')
        self.utility.write_log(20, '[In] Explore mutated FQDN using Google Hack [{}].'.format(self.file_name))

        # Explore FQDN using gathered domain list.
        used_domain_list = []
        fqdn_list = []
        for fqdn in origin_fqdn_list:
            # Mutate "jp" suffix -> "foreign" suffix.
            domain = ''
            ext = tldextract.extract(fqdn)
            suffix = ext.suffix
            if suffix == 'co.jp':
                domain = ext.domain + '.com'
            elif suffix == 'ne.jp':
                domain = ext.domain + '.net'
            elif suffix == 'or.jp':
                domain = ext.domain + '.org'
            elif suffix == 'ed.jp':
                domain = ext.domain + '.edu'
            elif suffix == 'go.jp':
                domain = ext.domain + '.gov'
            elif suffix == 'jp':
                domain = ext.domain + '.com'
            elif suffix == 'com':
                domain = ext.domain + '.co.jp'
            elif suffix == 'net':
                domain = ext.domain + '.ne.jp'
            elif suffix == 'org':
                domain = ext.domain + '.or.jp'
            elif suffix == 'edu':
                domain = ext.domain + '.ed.jp'
            elif suffix == 'gov':
                domain = ext.domain + '.go.jp'
            else:
                self.utility.print_message(WARNING, 'Don\'t define suffix : {}'.format(suffix))
                continue

            # Execute Google Custom Search.
            if domain not in used_domain_list:
                fqdn_list.extend(google_hack.search_domain(domain.lower(), self.max_search_num))
            else:
                self.utility.print_message(WARNING, 'Already searched domain : {}'.format(domain))
            used_domain_list.append(domain)

        # Extract FQDN.
        fqdn_list = list(set(fqdn_list))
        mutated_fqdn_list = self.check_black_list(fqdn_list)

        self.utility.write_log(20, '[Out] Explore mutated FQDN using Google Hack [{}].'.format(self.file_name))
        return mutated_fqdn_list

    # Explore FQDN using JPNIC.
    def jpnic_fqdn_explore(self, google_hack, keyword):
        self.utility.print_message(NOTE, 'Explore FQDN using JPNIC.')
        self.utility.write_log(20, '[In] Explore FQDN using JPNIC [{}].'.format(self.file_name))

        # Send request for gathering IP range list.
        ip_range_list = []
        self.jpnic_post['key'] = keyword
        res, _, _, res_body, _ = self.utility.send_request('POST',
                                                           self.jpnic_url,
                                                           body_param=self.jpnic_post,
                                                           enc='shift_jis')
        if res.status == 200:
            ip_range_list = re.findall(self.jpnic_regex_multi.format(keyword), res_body, flags=re.IGNORECASE)

        self.utility.write_log(20, '[Out] Explore FQDN using JPNIC [{}].'.format(self.file_name))
        return ip_range_list

    # Execute nslookup command.
    def execute_nslookup(self, target_fqdn, option, os_index, char_code):
        self.utility.write_log(20, '[In] Execute nslookup command [{}].'.format(self.file_name))

        # Execute nslookup command.
        nslookup_result = ''
        nslookup_cmd = self.nslookup_cmd + option + ' ' + target_fqdn
        try:
            self.utility.write_log(20, 'Execute : {}'.format(nslookup_cmd))
            nslookup_result = subprocess.check_output(nslookup_cmd, shell=True)
            self.utility.print_message(OK, 'Execute : {}'.format(nslookup_cmd))
        except Exception as e:
            msg = 'Executing {} is failure.'.format(nslookup_cmd)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)

        # Check nslookup result.
        fqdn_list = []
        nslookup_result = nslookup_result.decode(char_code)
        if nslookup_result != '':
            fqdn_list.extend(re.findall(self.cname_regex[os_index], nslookup_result))
            fqdn_list.extend(re.findall(self.mx_rec_regex[os_index], nslookup_result))
            fqdn_list.extend(re.findall(self.mx_rec_regex_multi[os_index], nslookup_result))
            fqdn_list.extend(re.findall(self.ns_rec_regex[os_index], nslookup_result))
            fqdn_list.extend(re.findall(self.soa_rec_regex[os_index], nslookup_result))
            fqdn_list.extend(re.findall(self.txt_rec_regex[os_index], nslookup_result))
        else:
            self.utility.print_message(WARNING, 'Executing nslookup is failure : {}.'.format(nslookup_cmd))

        if len(fqdn_list) != 0:
            self.utility.print_message(OK, 'Gathered : {}'.format(fqdn_list))

        self.utility.write_log(20, '[Out] Execute nslookup command [{}].'.format(self.file_name))
        return fqdn_list

    # Explore FQDN using DNS server.
    def dns_explore(self, target_fqdn_list):
        self.utility.print_message(NOTE, 'Explore FQDN using DNS server.')
        self.utility.write_log(20, '[In] Explore FQDN using DNS server [{}].'.format(self.file_name))

        # Set character code.
        char_code = ''
        os_index = 0
        if os.name == 'nt':
            char_code = 'shift-jis'
        else:
            char_code = 'utf-8'
            os_index = 1

        # Get Network addresses from each domain.
        dns_fqdn_list = []
        for target_fqdn in target_fqdn_list:
            for option in self.nslookup_options:
                dns_fqdn_list.extend(self.execute_nslookup(target_fqdn, option, os_index, char_code))
                time.sleep(self.nslookup_delay_time)

        self.utility.write_log(20, '[Out] Explore FQDN using DNS server [{}].'.format(self.file_name))
        return list(set(dns_fqdn_list))

    # Explore relevant domain.
    def fqdn_explore(self, spider, google_hack, target_url, keyword):
        self.utility.print_message(NOTE, 'Explore relevant domain.')
        self.utility.write_log(20, '[In] Explore relevant domain [{}].'.format(self.file_name))
        fqdn_list = []

        # Explore FQDN using Web Crawl and Google Custom Search.
        link_fqdn_list, non_link_fqdn_list = self.link_explorer(spider, google_hack, target_url, keyword)

        # Explore domain using JPRS.
        jprs_fqdn_list = self.jprs_fqdn_explore(google_hack, keyword)

        # Explore mutated fqdn.
        mutated_fqdn_list = self.mutated_fqdn_explore(google_hack, list(set(jprs_fqdn_list.extend(link_fqdn_list))))

        # Explore domain using JPNIC.
        # jpnic_fqdn_list = self.jpnic_fqdn_explore(google_hack, keyword)
        # TODO: IPレンジの探索機能を実装する。

        # Explore FQDN (DNS server, Mail server etc) using DNS server.
        target_fqdn_list = []
        target_fqdn_list.extend(link_fqdn_list)
        target_fqdn_list.extend(jprs_fqdn_list)
        # target_fqdn_list.extend(jpnic_fqdn_list)
        dns_fqdn_list = self.dns_explore(list(set(target_fqdn_list)))

        self.utility.write_log(20, '[Out] Explore relevant domain [{}].'.format(self.file_name))
        return list(set(fqdn_list))
