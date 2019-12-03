#!/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import copy
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
                               'microsoft@internet_information_server', 'microsoft@asp.net', 'wordpress@wordpress']

        try:
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

    # Create exploit's report
    def get_target_report(self):
        # Gather reporting items.
        csv_file_list = glob.glob(self.in_report)

        # Create DataFrame.
        content_list = []
        try:
            for file in csv_file_list:
                content_list.append(pd.read_csv(file, names=self.header, sep=','))
            df_csv = pd.concat(content_list).drop_duplicates().sort_values(by=['ip', 'port'], ascending=True).reset_index(drop=True, col_level=1)
        except Exception as e:
            self.utility.print_message(FAIL, 'Invalid file error: {}'.format(e))
            return


# main.
if __name__ == '__main__':
    merge = MergeReport(Utilty())

    # Create report header.
    merge.create_report_header()

    # Merge report.
    merge.get_target_report()

    print(2)
