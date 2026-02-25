#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import configparser
from censys.search import CensysHosts, CensysCerts
from censys.common.exceptions import CensysException

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
            # Using CensysHosts (v2)
            hosts = CensysHosts(api_id=self.api_id, api_secret=self.secret)
            self.utility.print_message(OK, 'Check open web ports.')

            # Extract search result.
            try:
                # Use view() to get details for the specific IP
                host = hosts.view(ip_addr)

                # 'services' is a list of dicts in v2
                services = host.get('services', [])
                for idx, service in enumerate(services):
                    port = service.get('port')
                    service_name = service.get('service_name', '').lower()
                    transport = service.get('transport_protocol', '').lower()

                    # Fallback if service_name is unknown
                    protocol = service_name if service_name != 'unknown' else transport

                    server_info.append({'Open Port': str(port), 'Protocol': protocol})
                    self.utility.print_message(WARNING, 'Open web port {}: {}/{}'.format(idx+1, port, protocol))

                    if protocol == 'https' or port == 443:
                        is_https = True
            except CensysException as e:
                self.utility.print_message(WARNING, 'Censys host view failed: {}'.format(e))


            # Check certification.
            if is_https is True:
                self.utility.print_message(OK, 'Check certification.')
                certificates = CensysCerts(api_id=self.api_id, api_secret=self.secret)

                # Query for trusted certificates matching the FQDN
                # "names" is the field for common name and SANs in v2
                query = 'tags: trusted and names: {}'.format(fqdn)

                # search returns an iterator of results
                for cert in certificates.search(query):
                    parsed = cert.get('parsed', {})

                    # Signature Algorithm
                    sig_alg = parsed.get('signature_algorithm', {}).get('name', 'Unknown')
                    self.utility.print_message(WARNING, 'Signature Algorithm: {}'.format(sig_alg))

                    # Subject info
                    subject = parsed.get('subject', {})

                    # Common Name
                    common_names = subject.get('common_name', [])
                    if isinstance(common_names, str):
                        common_names = [common_names]
                    for idx, common_name in enumerate(common_names):
                        self.utility.print_message(WARNING, 'Common Name {}: {}'.format(idx+1, common_name))

                    # Validity
                    validity = parsed.get('validity', {})
                    valid_start = validity.get('start', '')
                    valid_end = validity.get('end', '')
                    self.utility.print_message(WARNING, 'Validity Start Date : {}'.format(valid_start))
                    self.utility.print_message(WARNING, 'Validity End Date   : {}'.format(valid_end))

                    # Organization
                    org_names = subject.get('organization', [])
                    if isinstance(org_names, str):
                        org_names = [org_names]
                    for idx, org_name in enumerate(org_names):
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
