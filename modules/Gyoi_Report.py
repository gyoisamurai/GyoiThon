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
            self.report_file_name = ''
            self.report_file_name_censys = ''
            self.report_file_name_invent = ''
            self.report_dir = os.path.join(self.root_path, config['Report']['report_path'])
            self.report_path = os.path.join(self.report_dir, config['Report']['report_name'])
            self.report_path_censys = os.path.join(self.report_dir, config['Report']['report_name_censys'])
            self.report_path_invent = os.path.join(self.report_dir, config['Report']['report_name_invent'])
            self.report_path_exploit = os.path.join(self.report_dir, config['Report']['report_name_exploit'])
            self.report_temp = config['Report']['report_temp']
            self.template = config['Report']['template']
            self.header = str(config['Report']['header']).split('@')
            self.header_censys = str(config['Report']['header_censys']).split('@')
            self.header_invent = str(config['Report']['header_invent']).split('@')
            self.header_exploit = str(config['Report']['header_exploit']).split('@')

        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Create report's header.
    def create_report_header(self, fqdn, port):
        self.utility.print_message(NOTE, 'Create report header : {}'.format(self.report_path))
        self.utility.write_log(20, '[In] Create report header [{}].'.format(self.file_name))

        self.report_file_name = self.report_path.replace('*', fqdn + '_' + str(port) + '_' + self.utility.get_random_token(10))
        pd.DataFrame([], columns=self.header).to_csv(self.report_file_name, mode='w', index=False, encoding='utf-8')
        self.utility.write_log(20, '[Out] Create report header [{}].'.format(self.file_name))

    # Create report's body.
    def create_report_body(self, url, fqdn, port, cloud, method, products, type, comments, errors, srv_header, log_file, date, test_url):
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
        record.insert(5, test_url)       # Origin URL.
        record.insert(6, url)            # Target URL.
        record.insert(7, '-')            # Vendor name.
        record.insert(8, '-')            # Product name.
        record.insert(9, '-')            # Product version.
        record.insert(10, '-')           # Trigger of identified product.
        record.insert(11, '-')           # Product category.
        record.insert(12, '-')           # CVE number of product.
        record.insert(13, login_prob)    # Login probability.
        record.insert(14, login_reason)  # Trigger of login page.
        record.insert(15, '-')           # Unnecessary comments.
        record.insert(16, '-')           # Unnecessary Error messages.
        record.insert(17, srv_header)    # Server header.
        record.insert(18, log_file)      # Path of log file.
        record.insert(19, date)          # Creating date.
        report.append(record)

        # Build prduct record.
        for product in products:
            product_record = copy.deepcopy(record)
            product_record[7] = product[1]
            product_record[8] = product[2]
            product_record[9] = product[3]
            product_record[10] = product[4]
            product_record[11] = product[0]
            product_record[12] = product[5]
            report.append(product_record)

        # Build comment record.
        for comment in comments:
            comment_record = copy.deepcopy(record)
            comment_record[15] = '"' + str(comment) + '"'
            report.append(comment_record)

        # Build error message record.
        for error in errors:
            error_record = copy.deepcopy(record)
            error_record[16] = '"' + str(error) + '"'
            report.append(error_record)

        # Output report.
        msg = 'Create report : {}'.format(self.report_file_name)
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)
        pd.DataFrame(report).to_csv(self.report_file_name, mode='a', header=False, index=False, encoding='utf-8')

        self.utility.write_log(20, '[Out] Create report body [{}].'.format(self.file_name))

    # Create Censys report.
    def create_censys_report(self, fqdn, port, server_info, cert_info, date):
        self.utility.print_message(NOTE, 'Create Censys report of {}.'.format(fqdn))
        self.utility.write_log(20, '[In] Create Censys report [{}].'.format(self.file_name))

        self.report_file_name_censys = self.report_path_censys.replace('*', fqdn + '_' +
                                                                       str(port) + '_' +
                                                                       self.utility.get_random_token(10))
        pd.DataFrame([], columns=self.header_censys).to_csv(self.report_file_name_censys, mode='w', index=False)

        # Build base structure.
        report = []
        record = []
        record.insert(0, fqdn)                                # FQDN.
        record.insert(1, self.utility.forward_lookup(fqdn))   # IP address.
        record.insert(2, '-')      # Category.
        record.insert(3, '-')      # Discover open_port.
        record.insert(4, '-')      # Discover protocol.
        record.insert(5, '-')      # Cert of signature algorithm.
        record.insert(6, '-')      # Cert of Common name.
        record.insert(7, '-')      # Cert of validity start date.
        record.insert(8, '-')      # Cert of validity end date.
        record.insert(9, '-')      # Cert of organization name.
        record.insert(10, date)    # Creating date.
        # report.append(record)

        # Build server information record.
        for info in server_info:
            port_record = copy.deepcopy(record)
            port_record[2] = 'Server Info'
            port_record[3] = info['Open Port']
            port_record[4] = info['Protocol']
            report.append(port_record)

        # Build certification record.
        for cert in cert_info:
            cert_record = copy.deepcopy(record)
            cert_record[2] = 'Certification Info'
            cert_record[5] = cert['Signature Algorithm']
            cert_record[6] = cert['Common Name']
            cert_record[7] = cert['Validty Date'][0]
            cert_record[8] = cert['Validty Date'][1]
            cert_record[9] = cert['Organization Name']
            report.append(cert_record)

        # Output report.
        msg = 'Create Censys report : {}'.format(self.report_file_name_censys)
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)
        pd.DataFrame(report).to_csv(self.report_file_name_censys, mode='a', header=False, index=False)

        self.utility.write_log(20, '[Out] Create Censys report [{}].'.format(self.file_name))

    # Create Inventory report.
    def create_inventory_report(self, fqdn_list, keyword, target_fqdn, date):
        self.utility.print_message(NOTE, 'Create Inventory report of {}.'.format(target_fqdn))
        self.utility.write_log(20, '[In] Create Inventory report [{}].'.format(self.file_name))

        self.report_file_name_invent = self.report_path_invent.replace('*', keyword + '_' +
                                                                       target_fqdn + '_' +
                                                                       self.utility.get_random_token(10))
        pd.DataFrame([], columns=self.header_invent).to_csv(self.report_file_name_invent, mode='w', index=False)

        # Build base structure.
        report = []
        for idx, get_fqdn in enumerate(fqdn_list['FQDN']):
            record = []
            record.insert(0, keyword)                      # Company name.
            record.insert(1, target_fqdn)                  # Original FQDN.
            record.insert(2, get_fqdn)                     # FQDN.
            record.insert(3, fqdn_list['Score'][idx])      # Score.
            record.insert(4, fqdn_list['Comment'][idx])    # Category.
            record.insert(5, fqdn_list['DNS info'][idx])   # Discover open_port.
            record.insert(6, date)                         # Creating date.
            report.append(record)

        # Output report.
        msg = 'Create Inventory report : {}'.format(self.report_file_name_invent)
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)
        pd.DataFrame(report).to_csv(self.report_file_name_invent, mode='a', header=False, index=False)

        self.utility.write_log(20, '[Out] Create Inventory report [{}].'.format(self.file_name))

    # Create exploit's report
    def create_all_inventory_report(self):
        self.utility.print_message(NOTE, 'Create All Inventory report.')
        self.utility.write_log(20, '[In] Create All Inventory report [{}].'.format(self.file_name))

        # Gather reporting items.
        csv_file_list = glob.glob(self.report_path_invent)

        # Create DataFrame.
        content_list = []
        try:
            for file in csv_file_list:
                content_list.append(pd.read_csv(file,
                                                names=self.header_invent,
                                                sep=',',
                                                encoding='utf-8',
                                                engine='python'))
            df_csv = pd.concat(content_list).drop_duplicates().sort_values(by=['confidence', 'company name'],
                                                                           ascending=False).reset_index(drop=True,
                                                                                                        col_level=1)

            # Output report.
            file_invent = self.report_path_invent.replace('*', 'all_' + self.utility.get_random_token(10))
            msg = 'Create All Inventory report : {}'.format(file_invent)
            self.utility.print_message(OK, msg)
            self.utility.write_log(20, msg)
            df_csv.to_csv(file_invent, mode='w', header=False, index=False)
        except Exception as e:
            self.utility.print_message(FAIL, 'Invalid file error: {}'.format(e.args))
            return

        self.utility.write_log(20, '[Out] Create All Inventory report [{}].'.format(self.file_name))

    # Create exploit's report
    def create_exploit_report(self, fqdn, port):
        # Gather reporting items.
        log_path_fqdn = os.path.join(os.path.join(self.root_path, 'logs'), fqdn + '_' + str(port))
        if os.path.exists(log_path_fqdn) is False:
            os.mkdir(log_path_fqdn)
        csv_file_list = glob.glob(os.path.join(log_path_fqdn, self.report_temp))

        # Create DataFrame.
        content_list = []
        try:
            for file in csv_file_list:
                content_list.append(pd.read_csv(file, names=self.header_exploit, sep=','))
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
        self.report_path_exploit = self.report_path_exploit.replace('*', fqdn + '_' +
                                                                    str(port) + '_' +
                                                                    self.utility.get_random_token(10))
        with open(self.report_path_exploit, 'w') as fout:
            fout.write(html)
