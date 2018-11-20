#!/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import copy
import glob
import configparser
import pandas as pd
from jinja2 import Environment, FileSystemLoader

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Create report.
class CreateReport:
    def __init__(self, utility):
        self.utility = utility
        # Read config file.
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.report_dir = os.path.join(self.root_path, config['Report']['report_path'])
            self.report_path = os.path.join(self.report_dir, config['Report']['report_name'])
            self.report_path_exploit = os.path.join(self.report_dir, config['Report']['report_name_exploit'])
            self.report_temp = config['Report']['report_temp']
            self.template = config['Report']['template']
            self.header = str(config['Report']['header']).split('@')

        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Create report's header.
    def create_report_header(self, fqdn, port, path):
        self.utility.print_message(NOTE, 'Create report header : {}'.format(self.report_path))
        self.utility.write_log(20, '[In] Create report header [{}].'.format(self.file_name))

        report_file_name = self.report_path.replace('*', fqdn + '_' + str(port) + '_' + path)
        pd.DataFrame([], columns=self.header).to_csv(report_file_name, mode='w', index=False)
        self.utility.write_log(20, '[Out] Create report header [{}].'.format(self.file_name))

    # Create report's body.
    def create_report_body(self, url, fqdn, path, port, cloud, method, products, type, comments, errors, srv_header, log_file, date):
        self.utility.print_message(NOTE, 'Create {}:{} report\'s body.'.format(fqdn, port))
        self.utility.write_log(20, '[In] Create report body [{}].'.format(self.file_name))

        # Build base structure.
        report = []
        login_prob = ''
        login_reason = ''
        if len(type) != 0:
            login_prob = 'Log : ' + type['ml']['prob'] + ' %\n' + 'Url : ' + type['url']['prob'] + ' %'
            login_reason = 'Log : ' + type['ml']['reason'] + '\n' + 'Url : ' + type['url']['reason']
        else:
            login_prob = '*'
            login_reason = '*'
        record = []
        record.insert(0, fqdn)                                # FQDN.
        record.insert(1, self.utility.forward_lookup(fqdn))   # IP address.
        record.insert(2, str(port))      # Port number.
        record.insert(3, cloud)          # Cloud service type.
        record.insert(4, method)         # Using method.
        record.insert(5, url)            # Target URL.
        record.insert(6, '-')            # Vendor name.
        record.insert(7, '-')            # Product name.
        record.insert(8, '-')            # Product version.
        record.insert(9, '-')            # Trigger of identified product.
        record.insert(10, '-')           # Product category.
        record.insert(11, '-')           # CVE number of product.
        record.insert(12, login_prob)    # Login probability.
        record.insert(13, login_reason)  # Trigger of login page.
        record.insert(14, '-')           # Unnecessary comments.
        record.insert(15, '-')           # Unnecessary Error messages.
        record.insert(16, srv_header)    # Server header.
        record.insert(17, log_file)      # Path of log file.
        record.insert(18, date)          # Creating date.
        report.append(record)

        # Build prduct record.
        for product in products:
            product_record = copy.deepcopy(record)
            product_record[6] = product[1]
            product_record[7] = product[2]
            product_record[8] = product[3]
            product_record[9] = product[4]
            product_record[10] = product[0]
            product_record[11] = product[5]
            report.append(product_record)

        # Build comment record.
        for comment in comments:
            comment_record = copy.deepcopy(record)
            comment_record[14] = comment
            report.append(comment_record)

        # Build error message record.
        for error in errors:
            error_record = copy.deepcopy(record)
            error_record[15] = error
            report.append(error_record)

        # Output report.
        msg = 'Create report : {}'.format(self.report_path)
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)
        report_file_name = self.report_path.replace('*', fqdn + '_' + str(port) + '_' + path)
        pd.DataFrame(report).to_csv(report_file_name, mode='a', header=False, index=False)

        self.utility.write_log(20, '[Out] Create report body [{}].'.format(self.file_name))

    # Create exploit's report
    def create_exploit_report(self, fqdn, port, path):
        # Gather reporting items.
        log_path_fqdn = os.path.join(os.path.join(self.root_path, 'logs'),
                                     fqdn + '_' + str(port) + '_' + path.replace('/', ''))
        if os.path.exists(log_path_fqdn) is False:
            os.mkdir(log_path_fqdn)
        csv_file_list = glob.glob(os.path.join(log_path_fqdn, self.report_temp))

        # Create DataFrame.
        content_list = []
        try:
            for file in csv_file_list:
                content_list.append(pd.read_csv(file, names=self.header, sep=','))
            df_csv = pd.concat(content_list).drop_duplicates().sort_values(by=['ip', 'port'], ascending=True).reset_index(drop=True, col_level=1)
        except Exception as e:
            self.utility.print_message(FAIL, 'Invalid file error: {}'.format(e))
            return

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
        env = Environment(loader=FileSystemLoader(self.report_dir))
        template = env.get_template(self.template)
        pd.set_option('display.max_colwidth', -1)
        html = template.render({'title': 'GyoiThon Scan Report', 'items': items})
        with open(self.report_path_exploit, 'w') as fout:
            fout.write(html)
