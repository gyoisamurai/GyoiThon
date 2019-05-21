#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import re
import codecs
import json
import glob
import zipfile
import shutil
import ssl
import urllib3
import configparser
import pandas as pd
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class CveExplorerNVD:
    def __init__(self, utility, is_no_update):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.ua = config['Common']['user-agent']
            self.con_timeout = float(config['CveExplorerNVD']['con_timeout'])
            self.max_cve_count = int(config['CveExplorerNVD']['max_cve_count'])
            self.vuln_db_dir = config['CveExplorerNVD']['vuln_db_dir']
            self.nvd_name = config['CveExplorerNVD']['nvd_name']
            self.nvd_db_header = str(config['CveExplorerNVD']['nvd_db_header']).split('@')
            self.nvd_year_name = config['CveExplorerNVD']['nvd_year_name']
            self.nvd_db_dir = os.path.join(self.full_path, self.vuln_db_dir)
            self.nvd_path = os.path.join(self.full_path, os.path.join(self.vuln_db_dir, self.nvd_name))
            self.nvd_year_path = os.path.join(self.full_path, os.path.join(self.vuln_db_dir, self.nvd_year_name))
            self.cve_year_list = config['CveExplorerNVD']['cve_years'].split('@')
            self.nvd_meta_url = config['CveExplorerNVD']['nvd_meta_url']
            self.nvd_zip_url = config['CveExplorerNVD']['nvd_zip_url']
            self.nvd_chk_date_regex = config['CveExplorerNVD']['nvd_chk_date_regex']
            self.nvd_chk_hash_regex = config['CveExplorerNVD']['nvd_chk_hash_regex']
            self.nvd_date_format = config['CveExplorerNVD']['nvd_date_format']
            self.headers = urllib3.make_headers(proxy_basic_auth=self.utility.proxy_user + ':' + self.utility.proxy_pass)
            self.db_colmns = {}
            self.action_name = 'CVE Explorer'
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

        # Set HTTP request header.
        self.http_req_header = {'User-Agent': self.ua,
                                'Connection': 'keep-alive',
                                'Accept-Language': 'ja,en-US;q=0.7,en;q=0.3',
                                'Accept-Encoding': 'gzip, deflate',
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                                'Upgrade-Insecure-Requests': '1',
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'Cache-Control': 'no-cache'}

        # Create/Get vulnerability data base.
        for idx, col_name in enumerate(self.nvd_db_header):
            self.db_colmns[idx] = col_name
        if is_no_update is True and os.path.exists(self.nvd_path):
            self.utility.print_message(WARNING, 'Skip updating vulnerability DB.')
            self.utility.print_message(WARNING, 'Load existing "{}".'.format(self.nvd_path))
            self.df_vuln_db = pd.read_csv(self.nvd_path, sep=',', encoding='utf-8')
        else:
            self.df_vuln_db = self.initialize_vuln_db()

    # Extract vulnerability information from NVD.
    def extract_vuln_info(self, cve_items, cve_year, last_modified_date):
        self.utility.write_log(20, '[In] Extract vulnerability information [{}]'.format(self.file_name))
        all_cve_list = []

        # Get last modified date.
        last_modified_date_value = last_modified_date

        for cve_item in cve_items['CVE_Items']:
            # Get problem type (ex. CWE-**).
            per_cve = cve_item['cve']
            problem_type_value = ''
            problems = per_cve['problemtype']['problemtype_data']
            for description in problems:
                for problem in description['description']:
                    problem_type_value = problem['value']

            # Get description of vulnerability.
            description_value = ''
            for description in per_cve['description']['description_data']:
                description_value = description['value']

            # Get CVSS score.
            cvss_score_v2_value = ''
            cvss_score_v3_value = ''
            impact = cve_item['impact']

            # CVSS v3 score.
            if 'baseMetricV3' in impact:
                cvss_score_v3_value = float(impact['baseMetricV3']['cvssV3']['baseScore'])
            else:
                cvss_score_v3_value = 0

            # CVSS v2 score.
            if 'baseMetricV2' in impact:
                cvss_score_v2_value = format(impact['baseMetricV2']['cvssV2']['baseScore'])
            else:
                cvss_score_v2_value = 0

            # Get data type and CVE id.
            data_type_value = per_cve['data_type']
            cve_id_value = per_cve['CVE_data_meta']['ID']

            # Get configuration of CPE 2.3.
            some_cpe = []
            for nodes in cve_item['configurations']['nodes']:
                if 'children' in nodes:
                    for child_node in nodes['children']:
                        if 'cpe_match' in child_node:
                            for cpe in child_node['cpe_match']:
                                some_cpe.append(cpe)
                else:
                    if 'cpe_match' in nodes:
                        for cpe in nodes['cpe_match']:
                            some_cpe.append(cpe)
            for per_cpe in some_cpe:
                cpe23_list = per_cpe['cpe23Uri'].split(':')
                category_value = cpe23_list[2]
                vendor_name_value = cpe23_list[3]
                product_name_value = cpe23_list[4]
                version_value = cpe23_list[5]
                update_value = cpe23_list[6]
                edition_value = cpe23_list[7]

                # Add each item to list.
                self.utility.print_message(OK, 'Extract CVE information : '
                                               '{}, Vendor={}, '
                                               'Product={}, Version={}'.format(cve_id_value,
                                                                               vendor_name_value,
                                                                               product_name_value,
                                                                               version_value))
                per_cve_list = []
                per_cve_list.append(last_modified_date_value)
                per_cve_list.append(data_type_value)
                per_cve_list.append(problem_type_value)
                per_cve_list.append(cve_id_value)
                per_cve_list.append(cvss_score_v2_value)
                per_cve_list.append(cvss_score_v3_value)
                per_cve_list.append(str(category_value).lower())
                per_cve_list.append(str(vendor_name_value).lower())
                per_cve_list.append(str(product_name_value).lower())
                per_cve_list.append(str(version_value).lower())
                per_cve_list.append(str(update_value).lower())
                per_cve_list.append(str(edition_value).lower())
                per_cve_list.append(description_value.replace('\r', ' ').replace('\n', ' '))
                all_cve_list.append(per_cve_list)

        # Create csv file.
        db_path = self.nvd_year_path.replace('*', cve_year)
        self.utility.write_log(20, 'Create yearly vulnerability database : {}.'.format(db_path))
        pd.DataFrame(all_cve_list).to_csv(db_path, header=False, index=False)
        self.utility.write_log(20, '[Out] Extract vulnerability information [{}]'.format(self.file_name))

    # Create vulnerability yearly data base:
    def create_vuln_yearly_db(self, cve_year, last_modified_date):
        # Get cve list from NVD.
        self.utility.write_log(20, '[In] Create yearly vulnerability database [{}]'.format(self.file_name))

        target_url = self.nvd_zip_url.replace('*', cve_year)
        tmp_file = os.path.join(self.nvd_db_dir, 'temp_' + cve_year + '.zip')

        # Download zip file (include cve list) and uncompress zip file.
        target_json_name = ''
        self.utility.write_log(20, 'Accessing : {}'.format(target_url))
        self.utility.print_message(OK, 'Get {} CVE list from {}'.format(cve_year, target_url))

        http = None
        ctx = ssl.create_default_context()
        ctx.set_ciphers('DEFAULT')
        # ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        if self.utility.proxy != '':
            self.utility.print_message(WARNING, 'Set proxy server: {}'.format(self.utility.proxy))
            if self.utility.proxy_user != '':
                headers = urllib3.make_headers(proxy_basic_auth=self.utility.proxy_user + ':' + self.utility.proxy_pass)
                http = urllib3.ProxyManager(timeout=self.con_timeout,
                                            headers=self.http_req_header,
                                            proxy_url=self.utility.proxy,
                                            proxy_headers=headers)
            else:
                http = urllib3.ProxyManager(timeout=self.con_timeout,
                                            headers=self.http_req_header,
                                            proxy_url=self.utility.proxy)
        else:
            http = urllib3.PoolManager(timeout=self.con_timeout,
                                       headers=self.http_req_header,
                                       ssl_version=ssl.PROTOCOL_TLS,
                                       ssl_context=ctx)

        try:
            with http.request('GET', target_url, preload_content=False) as res, open(tmp_file, 'wb') as fout:
                shutil.copyfileobj(res, fout)
        except Exception as e:
            self.utility.print_exception(e, 'Access is failure : {}'.format(target_url))
            self.utility.write_log(30, 'Accessing is failure : {}'.format(target_url))

        with zipfile.ZipFile(tmp_file, 'r') as downloaded_zip:
            target_json_name = downloaded_zip.namelist()[0]
            downloaded_zip.extractall(self.nvd_db_dir)
        os.remove(tmp_file)

        # Create cve list of cve file.
        yearly_cve_list = []
        with codecs.open(os.path.join(self.nvd_db_dir, target_json_name), 'r', encoding='utf-8') as fin:
            self.extract_vuln_info(json.loads(fin.read().replace('\0', '')), cve_year, last_modified_date)

        self.utility.write_log(20, '[Out] Create yearly vulnerability database [{}]'.format(self.file_name))
        return yearly_cve_list

    # Initialize Vulnerability Data Base.
    def initialize_vuln_db(self):
        # Get vulnerabilities information.
        self.utility.write_log(20, '[In] Initialize vulnerability database [{}].'.format(self.file_name))

        update_flag = False
        for cve_year in self.cve_year_list:
            # Get last modified date and file hash.
            try:
                # Get meta information.
                target_url = self.nvd_meta_url.replace('*', cve_year)
                self.utility.print_message(OK, 'Get {} meta information from {}'.format(cve_year, target_url))
                self.utility.write_log(20, 'Accessing : {}'.format(target_url))
                res_meta, _, _, _, encoding = self.utility.send_request('GET', target_url)
                obj_match = re.match(self.nvd_chk_date_regex, res_meta.data.decode(encoding))
                last_modified_date = obj_match.group(obj_match.lastindex)

                year_db = self.nvd_year_path.replace('*', cve_year)
                if os.path.exists(year_db) is True:
                    # Get existing data base.
                    df_year_db = pd.read_csv(year_db,
                                             sep=',',
                                             names=self.nvd_db_header,
                                             header=None,
                                             encoding='utf-8').fillna('')

                    # Check last modified date.
                    db_cve_date = self.utility.transform_date_object(df_year_db['last_modified_date'][0],
                                                                     self.nvd_date_format)
                    currently_cve_date = self.utility.transform_date_object(last_modified_date, self.nvd_date_format)
                    if db_cve_date < currently_cve_date:
                        # Create vulnerability data base.
                        self.utility.print_message(OK, 'Update {} : latest date={}, last modified date={}'.
                                                   format(year_db,
                                                          currently_cve_date.strftime(self.nvd_date_format),
                                                          db_cve_date.strftime(self.nvd_date_format)))
                        self.create_vuln_yearly_db(cve_year, last_modified_date)
                        update_flag = True
                    else:
                        self.utility.print_message(FAIL, 'Skip updating {} : no update from {}'.
                                                   format(year_db, db_cve_date.strftime(self.nvd_date_format)))
                else:
                    # Create vulnerability data base.
                    self.create_vuln_yearly_db(cve_year, last_modified_date)
                    update_flag = True
            except Exception as e:
                self.utility.print_exception(e, 'Getting last modified date is failure.')
                self.utility.write_log(30, 'Getting last modified date is failure.')

        df_vuln_db = None
        if update_flag is True:
            try:
                # Load updating vulnerability data base each year.
                self.utility.print_message(OK, 'Create vulnerability database : {}'.format(self.nvd_path))
                year_csv_list = glob.glob(os.path.join(self.nvd_db_dir, self.nvd_year_name))

                # Create DataFrame.
                cve_list = []
                for file in year_csv_list:
                    cve_list.append(pd.read_csv(file, sep=',', header=None, encoding='utf-8').fillna(''))
                if len(cve_list) != 0:
                    # Create new vulnerability data base.
                    df_vuln_db = pd.concat(cve_list).rename(columns=self.db_colmns).sort_values(by=['cvss_v3_score',
                                                                                                    'cvss_v2_score'],
                                                                                                ascending=False)
                    df_vuln_db.to_csv(self.nvd_path, mode='w', index=False)
            except Exception as e:
                self.utility.print_exception(e, 'Creating vulnerability database is failure : {}.'.format(e))
                self.utility.write_log(30, 'Creating vulnerability database is failure : {}.'.format(e))
        else:
            # Load existing vulnerability data base.
            self.utility.print_message(OK, 'Load vulnerability database : {}'.format(self.nvd_path))
            df_vuln_db = pd.read_csv(self.nvd_path, sep=',', encoding='utf-8')

        self.utility.write_log(20, '[Out] Initialize vulnerability database [{}].'.format(self.file_name))
        return df_vuln_db

    # Explore CVE information.
    def cve_explorer(self, product_list):
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Explore CVE information',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        for prod_idx, product in enumerate(product_list):
            self.utility.print_message(NOTE, 'Explore CVE of {}/{} from NVD.'.format(product[1], product[2]))

            df_selected_cve = None
            cve_info = ''
            if product[1] != '*' and product[3] != '*':
                df_selected_cve = self.df_vuln_db[(self.df_vuln_db['vendor_name'] == product[1]) &
                                                  (self.df_vuln_db['product_name'] == product[2]) &
                                                  (self.df_vuln_db['version_value'] == product[3])]
            elif product[1] != '*' and product[3] == '*':
                df_selected_cve = self.df_vuln_db[(self.df_vuln_db['vendor_name'] == product[1]) &
                                                  (self.df_vuln_db['product_name'] == product[2])]
            elif product[1] == '*' and product[3] != '*':
                df_selected_cve = self.df_vuln_db[(self.df_vuln_db['product_name'] == product[2]) &
                                                  (self.df_vuln_db['version_value'] == product[3])]
            else:
                df_selected_cve = self.df_vuln_db[(self.df_vuln_db['product_name'] == product[2])]
            for cve_idx, cve_id in enumerate(df_selected_cve['id'].drop_duplicates()):
                msg = 'Find {} for {}/{} {}.'.format(cve_id, product[1], product[2], product[3])
                self.utility.print_message(WARNING, msg)
                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note=msg,
                                                dest=self.utility.target_host)
                self.utility.write_log(30, msg)
                cve_info += cve_id + '\n'
                if cve_idx == (self.max_cve_count - 1):
                    break
            # Insert CVE to product list.
            if cve_info == '':
                cve_info = 'Cannot search.'
            product_list[prod_idx].insert(len(product), cve_info)

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Explore CVE information',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return product_list
