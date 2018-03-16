#!/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import glob
import configparser
import pandas as pd
from jinja2 import Environment, FileSystemLoader


# Create report.
class CreateReport:
    def __init__(self):
        # Read config file.
        config = configparser.ConfigParser()
        full_path = os.path.dirname(os.path.abspath(__file__))
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            print('File exists error: {0}'.format(err))
            sys.exit(1)

        self.report_path = os.path.join(full_path, config['GyoiReport']['report_path'])
        self.report_name = os.path.join(self.report_path, config['GyoiReport']['report_name'])
        self.template = config['GyoiReport']['template']
        self.header = str(config['GyoiReport']['header']).split('@')

    def create_report(self):
        # Gather reporting items.
        csv_file_list = glob.glob(os.path.join(self.report_path, '*.csv'))

        # Create DataFrame.
        content_list = []
        try:
            for file in csv_file_list:
                content_list.append(pd.read_csv(file, names=self.header, sep=','))
            df_csv = pd.concat(content_list).drop_duplicates().sort_values(by=['ip', 'port'], ascending=True).reset_index(drop=True, col_level=1)
        except Exception as err:
            print('Invalid file error: {0}'.format(err))
            sys.exit(1)

        items = []
        for idx in range(len(df_csv)):
            items.append({'ip_addr': df_csv.loc[idx, 'ip'],
                          'port': df_csv.loc[idx, 'port'],
                          'prod_name': df_csv.loc[idx, 'service'],
                          'vuln_name': df_csv.loc[idx, 'vuln_name'],
                          'type': df_csv.loc[idx, 'type'],
                          'description': df_csv.loc[idx, 'description'],
                          'exploit': df_csv.loc[idx, 'exploit'],
                          'target': df_csv.loc[idx, 'target'],
                          'payload': df_csv.loc[idx, 'payload'],
                          'ref': str(df_csv.loc[idx, 'reference']).replace('@', '<br>')})

        # Setting template.
        env = Environment(loader=FileSystemLoader(self.report_path))
        template = env.get_template(self.template)
        pd.set_option('display.max_colwidth', -1)
        html = template.render({'title': 'GyoiThon Scan Report', 'items': items})
        with open(self.report_name, 'w') as fout:
            fout.write(html)


if __name__ == '__main__':
    report = CreateReport()
    report.create_report()
    print(os.path.basename(__file__) + ' finish!!')
