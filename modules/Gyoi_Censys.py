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
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.api_id = config['Censys']['api_id']
            self.secret = config['Censys']['secret']
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Control censys.
    def search_censys(self, protocol, ip_addr, fqdn):
        self.utility.print_message(NOTE, 'Search Censys.')
        self.utility.write_log(20, '[In] Search Censys [{}].'.format(self.file_name))

        api = censys.ipv4.CensysIPv4(api_id=self.api_id, api_secret=self.secret)
        self.utility.print_message(OK, 'Check open web ports.')
        for result in api.search('ip:{}'.format(ip_addr)):
            self.utility.print_message(WARNING, 'Open web ports: {}'.format(result['protocols']))

        # Check cloud service name.
        if protocol == 'https':
            self.utility.print_message(OK, 'Check certification.')
            api = censys.certificates.CensysCertificates(api_id=self.api_id, api_secret=self.secret)
            fields = ['parsed.subject_dn', 'parsed.validity', 'parsed.signature_algorithm', 'parsed.subject']
            for cert in api.search('tags: trusted and parsed.names: {}'.format(fqdn), fields=fields):
                self.utility.print_message(WARNING, 'Sig Algorithm: {}'.format(cert['parsed.signature_algorithm.name']))
                for idx, common_name in enumerate(cert['parsed.subject.common_name']):
                    self.utility.print_message(WARNING, 'Common Name {}: {}'.format(idx+1, common_name))
                self.utility.print_message(WARNING, 'Validity Start: {}'.format(cert['parsed.validity.start']))
                self.utility.print_message(WARNING, 'Validity End  : {}'.format(cert['parsed.validity.end']))
                for idx, org_name in enumerate(cert['parsed.subject.organization']):
                    self.utility.print_message(WARNING, 'Organization {}: {}'.format(idx+1, org_name))

        self.utility.write_log(20, '[Out] Search Censys [{}].'.format(self.file_name))
