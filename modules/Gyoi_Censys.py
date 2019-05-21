#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import configparser
import censys
from censys import *

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class Censys:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        self.action_name = 'Censys'
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.api_id = config['Censys']['api_id']
            self.secret = config['Censys']['secret']
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Control censys.
    def search_censys(self, ip_addr, fqdn):
        self.utility.print_message(NOTE, 'Search Censys.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Search Censys',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        server_info = []
        cert_info = []
        try:
            # Check network expose information.
            is_https = False
            api = censys.ipv4.CensysIPv4(api_id=self.api_id, api_secret=self.secret)
            self.utility.print_message(OK, 'Check open web ports.')

            # Extract search result.
            for result in api.search('ip:{}'.format(ip_addr)):
                for idx, items in enumerate(result['protocols']):
                    # Get port number and protocol type.
                    server_info.append({'Open Port': items.split('/')[0], 'Protocol': items.split('/')[1]})
                    self.utility.print_message(WARNING, 'Open web port {}: {}'.format(idx+1, items))
                    if items.split('/')[1] == 'https':
                        is_https = True

            # Check certification.
            if is_https is True:
                self.utility.print_message(OK, 'Check certification.')
                api = censys.certificates.CensysCertificates(api_id=self.api_id, api_secret=self.secret)
                fields = ['parsed.subject_dn', 'parsed.validity', 'parsed.signature_algorithm', 'parsed.subject']

                # Extract search result.
                for cert in api.search('tags: trusted and parsed.names: {}'.format(fqdn), fields=fields):
                    # Get signature algorithm.
                    sig_alg = cert['parsed.signature_algorithm.name']
                    self.utility.print_message(WARNING, 'Signature Algorithm: {}'.format(sig_alg))

                    # Get common name.
                    common_names = []
                    for idx, common_name in enumerate(cert['parsed.subject.common_name']):
                        common_names.append(common_name)
                        self.utility.print_message(WARNING, 'Common Name {}: {}'.format(idx+1, common_name))

                    # Get validity start and end date.
                    valid_start = cert['parsed.validity.start']
                    valid_end = cert['parsed.validity.end']
                    self.utility.print_message(WARNING, 'Validity Start Date : {}'.format(valid_start))
                    self.utility.print_message(WARNING, 'Validity End Date   : {}'.format(valid_end))

                    # Get organization name.
                    org_names = []
                    for idx, org_name in enumerate(cert['parsed.subject.organization']):
                        org_names.append(org_name)
                        self.utility.print_message(WARNING, 'Organization Name {}: {}'.format(idx+1, org_name))

                    cert_info.append({'Signature Algorithm': sig_alg,
                                      'Common Name': common_names,
                                      'Validty Date': [valid_start, valid_end],
                                      'Organization Name': org_names})

            if len(server_info) == 0:
                self.utility.print_message(WARNING, 'Cannot search {} information using Censys'.format(fqdn))
        except Exception as e:
            self.utility.print_message(FAIL, 'Censys execution is failure : {}'.format(e))
            self.utility.write_log(30, 'Censys execution is failure : {}'.format(e))

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Search Censys',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return server_info, cert_info
