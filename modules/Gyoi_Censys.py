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
        for result in api.search('ip:{}'.format(ip_addr)):
            self.utility.print_message(OK, 'Open web ports: {}'.format(result['protocols']))

        # Check cloud service name.
        if protocol == 'https':
            api = censys.certificates.CensysCertificates(api_id=self.api_id, api_secret=self.secret)
            fields = ["parsed.subject_dn", "parsed.fingerprint_sha256"]
            for cert in api.search('tags: trusted and parsed.names: {}'.format(fqdn), fields=fields):
                self.utility.print_message(OK, 'Certification info: {}'.format(cert))

        self.utility.write_log(20, '[Out] Search Censys [{}].'.format(self.file_name))
