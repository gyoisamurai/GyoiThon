#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import traceback
import re
import codecs
import glob
import configparser
import pandas as pd
from util import Utilty

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Merge report.
class MergeReport:
    def __init__(self, utility):
        self.utility = utility
        # Read config file.
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        config.read(os.path.join(self.full_path, 'config.ini'))

        # Define report header.
        self.header = ['No', '海外/国内', '会社名/組織名', 'カテゴリ', 'FQDN (URL)', 'リダイレクト/トップURL (URL)',
                       'ソース (URL)', 'FQDN (IPアドレス)', 'トップURL (IPアドレス)', 'フォーム (認証)', 'Basic (認証)',
                       '開発/本番 (環境)', 'クラウド (環境)', '製品 (CMS)', '管理画面 (CMS)', '不要なコンテンツ',
                       'ディレクトリ一覧の表示', 'エラーメッセージ', '不適切なコメント', 'Apache (製品)', 'PHP (製品)',
                       'OpenSSL (製品)', 'nginx (製品)', 'IIS (製品)', '.NET (製品)',
                       'MVC (製品)', 'WordPress (製品)', 'その他 (製品)', '備考']

        # Must product name.
        self.require_prduct = ['apache@http_server', 'php@php', 'openssl@openssl', 'nginx@nginx',
                               'microsoft@internet_information_server', 'microsoft@asp.net', 'microsoft@mvc',
                               'wordpress@wordpress']

        # Basic authentication regex.
        self.basic_regex = 'WWW-Authenticate\:\s(Basic|Bearer|Digest|HOBA|Mutual|AWS4-HMAC-SHA256)\s'
        self.basic_proxy_regex = 'Proxy-Authenticate\:\s(Basic|Bearer|Digest|HOBA|Mutual|AWS4-HMAC-SHA256)\s'

        try:
            self.local_header = (config['Report']['header']).split('@')
            self.report_dir = os.path.join(self.full_path, config['Report']['report_path'])
            self.in_report = os.path.join(self.report_dir, config['Report']['report_name'])
            out_report_name = 'gyoithon_merge_report_{}.csv'.format(self.utility.get_current_date('%Y%m%d%H%M%S'))
            self.out_report = os.path.join(self.report_dir, out_report_name)
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Create report's header.
    def create_report_header(self):
        self.utility.print_message(NOTE, 'Create report header : {}'.format(self.out_report))
        self.utility.write_log(20, '[In] Create report header [{}].'.format(self.out_report))

        # Create report header.
        if os.path.exists(self.out_report) is False:
            pd.DataFrame([], columns=self.header).to_csv(self.out_report, mode='w', index=False, encoding='Shift_JIS')

        self.utility.write_log(20, '[Out] Create report header [{}].'.format(self.out_report))

    # Get target report (local report).
    def get_target_report(self):
        # Gather reporting items.
        csv_file_list = glob.glob(self.in_report)

        # Create DataFrame.
        try:
            for report_idx, file in enumerate(csv_file_list):
                self.utility.print_message(OK, '{}/{} Processing: {}'.format(report_idx+1, len(csv_file_list), file))
                record = []
                df_local = pd.read_csv(file, names=self.local_header, header=0, sep=',')
                record.append(self.extract_report_element(report_idx+1, df_local))

                # Add record.
                pd.DataFrame(record).to_csv(self.out_report, mode='a', header=False, index=False, encoding='Shift_JIS')
        except Exception as e:
            t, v, tb = sys.exc_info()
            self.utility.print_message(FAIL, 'Invalid file error: {}'.format(e))
            self.utility.print_message(FAIL, traceback.format_exception(t, v, tb))
            self.utility.print_message(FAIL, traceback.format_tb(e.__traceback__))
            return

    # Extract report's element from local reports.
    def extract_report_element(self, report_idx, df_local):
        record = []
        record.insert(0, report_idx)                  # No.
        record.insert(1, '-')                         # 海外/国内
        record.insert(2, '-')                         # 会社名/組織名
        record.insert(3, '-')                         # カテゴリ
        record.insert(4, df_local['fqdn'][0])         # FQDN.
        record.insert(5, df_local['origin_url'][0])   # トップURL
        record.insert(6, '-')                         # ソース
        record.insert(7, df_local['ip_addr'][0])      # FQDN.
        origin_url_ip = (df_local['origin_url'][0]).replace(df_local['fqdn'][0], df_local['ip_addr'][0], 1)
        record.insert(8, origin_url_ip)               # トップURL.

        # Check login form.
        if self.check_login_form(df_local):
            record.insert(9, '有')
        else:
            record.insert(9, '-')

        # Check Basic authentication.
        if self.check_basic_auth(df_local):
            record.insert(10, '有')
        else:
            record.insert(10, '-')

        record.insert(11, '-')                         # 開発/本番
        record.insert(12, df_local['cloud_type'][0])   # クラウド

        # Check CMS product.
        cms_info = list(map(list, set(map(tuple, self.check_cms(df_local)))))
        if len(cms_info) != 0:
            cms_product = []
            cms_manage_page = []
            for cms in cms_info:
                cms_product.append(cms[0])
                cms_manage_page.append(cms[1])
            record.insert(13, '\n'.join(cms_product))      # CMS 製品名
            record.insert(14, '\n'.join(cms_manage_page))  # 管理画面
        else:
            record.insert(13, '-')
            record.insert(14, '-')

        # Check unnecessary contents.
        record.insert(15, '\n'.join(self.check_unnecessary_content(df_local)))

        record.insert(16, '-')  # TODO:ディレクトリ一覧の表示

        # Unnecessary comment and error message.
        un_comment, error_msg = self.check_comment_error(df_local)
        record.insert(17, '\n'.join(error_msg))
        record.insert(18, '\n'.join(un_comment))

        # Check products.
        require_list, other_list = self.check_require_prduct(df_local)
        for idx in range(len(require_list)):
            if idx == 0:      # Apache
                self.set_require_prod(idx, 19, require_list, record)
            elif idx == 1:    # PHP
                self.set_require_prod(idx, 20, require_list, record)
            elif idx == 2:    # OpenSSL
                self.set_require_prod(idx, 21, require_list, record)
            elif idx == 3:    # nginx
                self.set_require_prod(idx, 22, require_list, record)
            elif idx == 4:    # IIS
                self.set_require_prod(idx, 23, require_list, record)
            elif idx == 5:    # .NET
                self.set_require_prod(idx, 24, require_list, record)
            elif idx == 6:    # MVC
                self.set_require_prod(idx, 25, require_list, record)
            elif idx == 7:    # WordPress
                self.set_require_prod(idx, 26, require_list, record)

        # Other products.
        if len(other_list) != 0:
            record.insert(27, '\n'.join(other_list))
        else:
            record.insert(27, '-')

        # Note.
        record.insert(28, '-')

        return record

    # Set requirement product.
    def set_require_prod(self, prod_idx, rec_idx, require_list, record):
        if require_list[prod_idx][0]:
            if require_list[prod_idx][1] != '*':
                record.insert(rec_idx, '\n'.join(require_list[prod_idx][1]))
            else:
                record.insert(rec_idx, '○')
        else:
            record.insert(rec_idx, '-')

    # Check login form.
    def check_login_form(self, df_local):
        df_login = df_local[df_local['origin_login'] != 'Log : - %\nUrl : 0.0 %']
        if len(df_login) != 0:
            return True
        else:
            return False

    # Check Basic authentication.
    def check_basic_auth(self, df_local):
        is_basic_auth = False
        for log_path in df_local['log']:
            with codecs.open(log_path, 'r', encoding='utf-8') as fin:
                log_file = fin.read()
                obj_match = re.search(self.basic_regex, log_file, flags=re.IGNORECASE)
                if obj_match is not None:
                    is_basic_auth = True
                    break
                obj_match = re.search(self.basic_proxy_regex, log_file, flags=re.IGNORECASE)
                if obj_match is not None:
                    is_basic_auth = True
                    break
        return is_basic_auth

    # Check CMS.
    def check_cms(self, df_local):
        cms_info = []
        df_cms = df_local[df_local['prod_type'] == 'CMS']
        if len(df_cms) != 0:
            for idx, cms_record in df_cms.iterrows():
                local_record = []
                local_record.insert(0, cms_record['prod_name'] + '/' + cms_record['prod_version'])
                if 'Url : 100%' in cms_record['origin_login']:
                    local_record.insert(1, cms_record['url'])
                else:
                    local_record.insert(1, '-')
                cms_info.append(local_record)
        return cms_info

    # Check unnecessary contents.
    def check_unnecessary_content(self, df_local):
        un_contents = df_local[(df_local['method'] == 'Direct') | (df_local['method'] == 'Search')]['url']
        return list(set(un_contents))

    # Check unnecessary comments and error messages.
    def check_comment_error(self, df_local):
        comments = list(set(df_local['wrong_comment']))
        error_msg = list(set(df_local['error_msg']))
        return [s for s in comments if s != '-'], [s for s in error_msg if s != '-']

    # Check require products.
    def check_require_prduct(self, df_local):
        # Apache, PHP, OpenSSL, nginx, IIS, ASP.NET, WordPress.
        require_list = {0: [False, []], 1: [False, []], 2: [False, []], 3: [False, []],
                        4: [False, []], 5: [False, []], 6: [False, []], 7: [False, []]}

        # Other products.
        other_list = []

        # Check Requirement products.
        for idx, target_product in enumerate(self.require_prduct):
            target_item = target_product.split('@')
            df_selected_record = df_local[(df_local['vendor_name'] == target_item[0]) &
                                          (df_local['prod_name'] == target_item[1])]
            version_list = []
            if len(df_selected_record) != 0:
                require_list[idx][0] = True
                for pd_idx, record in df_selected_record.iterrows():
                    if record['prod_version'] != '*':
                        version_list.append('"' + str(record['prod_version']) + '"')
                require_list[idx][1].extend(list(set(version_list)))

        # Check other products.
        df_rec = df_local[~((df_local['vendor_name'] == 'apache') & (df_local['prod_name'] == 'http_server')) &
                          ~((df_local['vendor_name'] == 'php') & (df_local['prod_name'] == 'php')) &
                          ~((df_local['vendor_name'] == 'openssl') & (df_local['prod_name'] == 'openssl')) &
                          ~((df_local['vendor_name'] == 'nginx') & (df_local['prod_name'] == 'nginx')) &
                          ~((df_local['vendor_name'] == 'microsoft') & (df_local['prod_name'] == 'internet_information_server')) &
                          ~((df_local['vendor_name'] == 'microsoft') & (df_local['prod_name'] == 'asp.net')) &
                          ~((df_local['vendor_name'] == 'microsoft') & (df_local['prod_name'] == 'mvc')) &
                          ~((df_local['vendor_name'] == 'wordpress') & (df_local['prod_name'] == 'wordpress'))]
        if len(df_rec) != 0:
            for other_idx, record in df_rec.iterrows():
                if record['prod_name'] != '-':
                    other_list.append(record['vendor_name'] + ' ' + record['prod_name'] + '/' + record['prod_version'])

        return require_list, list(set(other_list))


# main.
if __name__ == '__main__':
    merge = MergeReport(Utilty())

    # Create report header.
    merge.create_report_header()

    # Merge report.
    merge.get_target_report()

    print('finish!!')
