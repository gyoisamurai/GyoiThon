#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import re
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
        config.read(os.path.join(self.root_path, 'config.ini'))

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
            self.jpnic_url = config['Inventory']['jpnic_url']
            self.jpnic_post = {'codecheck-sjis': 'にほんねっとわーくいんふぉめーしょんせんたー',
                               'key': '', 'submit': '検索', 'type': 'NET-HOLDER', 'rule': ''}
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Check black list.
    def check_black_list(self, fqdn_list):
        for idx, fqdn in enumerate(fqdn_list):
            for exclude_fqdn in enumerate(self.black_list):
                if fqdn == exclude_fqdn.replace('\n', '').replace('\r', ''):
                    del fqdn_list[idx]
                    self.utility.print_message(WARNING, '"{}" is include black list.'.format(fqdn))
        return fqdn_list

    # Explore relevant link.
    def link_explorer(self, spider, google_hack, target_url, keyword, encoding):
        self.utility.print_message(NOTE, 'Explore relevant FQDN.')
        self.utility.write_log(20, '[In] Explore relevant FQDN [{}].'.format(self.file_name))

        parsed = util.parse_url(target_url)

        # Gather FQDN from link of target web site.
        link_fqdn_list = []
        spider.utility.encoding = encoding
        _, url_list = spider.run_spider(parsed.scheme, parsed.host, parsed.port, parsed.path)
        for url in url_list:
            parsed = util.parse_url(url)
            link_fqdn_list.append(parsed.host)
        link_fqdn_list = self.check_black_list(list(set(link_fqdn_list)))

        # Search FQDN that include link to the target FQDN using Google Custom Search.
        non_reverse_link_fqdn = []
        for del_idx, search_fqdn in enumerate(link_fqdn_list):
            # Check reverse link to target FQDN.
            if google_hack.search_relevant_fqdn(parsed.host, search_fqdn) is False:
                non_reverse_link_fqdn.append(link_fqdn_list[del_idx])
                del link_fqdn_list[del_idx]

        # Search related FQDN using Google Custom Search.
        related_fqdn_list = []
        for url in google_hack.search_related_fqdn(parsed.host, keyword, self.max_search_num):
            parsed = util.parse_url(url)
            related_fqdn_list.append(parsed.host)
        related_fqdn_list = self.check_black_list(list(set(related_fqdn_list)))

        self.utility.write_log(20, '[Out] Explore relevant FQDN [{}].'.format(self.file_name))
        return list(set(link_fqdn_list.extend(related_fqdn_list))), non_reverse_link_fqdn

    # Explore Domain.
    def domain_explore(self, google_hack, keyword):
        self.utility.print_message(NOTE, 'Explore relevant domain.')
        self.utility.write_log(20, '[In] Explore relevant domain [{}].'.format(self.file_name))

        # Explore domain using JPRS.
        self.utility.print_message(OK, 'Explore domain from JPRS.')
        domain_list = []
        self.jprs_post['key'] = keyword
        res, _, _, res_body, _ = self.utility.send_request('POST',
                                                           self.jprs_url,
                                                           body_param=self.jprs_post)
        if res.status == 200:
            domain_list = re.findall(r'{}.*\s*<a.*>(.*)</a>[\r\n]'.format(keyword), res_body)
            if len(domain_list) == 0:
                domain_list = re.findall(r'\[ドメイン名\]\s+([\w\Wa-zA-Z\.].*)[\r\n]', res_body)
                if len(domain_list) != 0:
                    self.utility.print_message(NOTE, 'Gathered domain from JPRS. : {}'.format(domain_list))
                else:
                    self.utility.print_message(WARNING, 'Could not gather domain from JPRS.')
            else:
                self.utility.print_message(NOTE, 'Gathered domain from JPRS. : {}'.format(domain_list))

        # Explore FQDN using gathered domain list.
        fqdn_list = []
        # for domain in list(set(domain_list)):
        #     fqdn_list.extend(google_hack.search_domain(domain.lower(), self.max_search_num))

        fqdn_list = list(set(fqdn_list))
        jprs_fqdn_list = []
        for url in fqdn_list:
            parsed = util.parse_url(url)
            jprs_fqdn_list.append(parsed.host)
        jprs_fqdn_list = list(set(jprs_fqdn_list))

        # Explore domain using JPNIC.
        domain_list = []
        self.jpnic_post['key'] = keyword
        res, _, _, res_body, _ = self.utility.send_request('POST',
                                                           self.jpnic_url,
                                                           body_param=self.jpnic_post,
                                                           enc='shift_jis')
        if res.status == 200:
            domain_list = re.findall(r'{}.*\s.*<a.*>(.*)</a>[\r\n]'.format(keyword), res_body, flags=re.IGNORECASE)

        # Explore FQDN using gathered domain list.
        fqdn_list = []
        for domain in list(set(domain_list)):
            fqdn_list.extend(google_hack.search_domain(domain.lower(), self.max_search_num))

        self.utility.write_log(20, '[Out] Explore relevant domain [{}].'.format(self.file_name))
        return list(set(fqdn_list))
