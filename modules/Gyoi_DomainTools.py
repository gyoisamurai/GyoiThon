#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import sys
import configparser
import json
import re
import hmac
import hashlib
from datetime import datetime
from util import Utilty

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class DomainTools:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        self.action_name = 'DomainTools'
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.api_host = config['DomainTools']['api_host']
            self.api_key = config['DomainTools']['api_key']
            self.api_username = config['DomainTools']['api_username']
            self.uri_reverse_whois = config['DomainTools']['uri_reverse_whois']
            self.uri_whois_lookup = config['DomainTools']['uri_whois_lookup']
            self.uri_reverse_nslookup = config['DomainTools']['uri_reverse_nslookup']
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Get timestamp.
    def timestamp(self):
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Create signature.
    def sign(self, timestamp, uri):
        params = ''.join([self.api_username, timestamp, uri])
        return hmac.new(self.api_key.encode('utf-8'), params.encode('utf-8'), digestmod=hashlib.sha1).hexdigest()

    # Reverse Whois.
    def reverse_whois(self, search_word):
        # Create target url.
        timestamp = self.timestamp()
        signature = self.sign(timestamp, self.uri_reverse_whois)
        target_url = 'https://{}{}?api_username={}&signature={}&timestamp={}&term={}'.format(self.api_host,
                                                                                             self.uri_reverse_whois,
                                                                                             self.api_username,
                                                                                             signature,
                                                                                             timestamp,
                                                                                             search_word)

        # Send request.
        res, _, _, res_body, _ = self.utility.send_request('GET', target_url)
        if res is None or res.status >= 400:
            self.utility.print_message(FAIL, 'Could not access to {}.'.format(target_url))
            return []

        # Convert from string to dictionary.
        res_json = {}
        if 'application/json' in res.headers['Content-Type']:
            res_json = json.loads(res_body)
        else:
            self.utility.print_message(FAIL, 'Invalid Content-Type :{}.'.format(res.headers['Content-Type']))
            return []

        # Extract domain list.
        domain_list = []
        if 'domains' in res_json.keys():
            domain_list = res_json['domains']

        return domain_list

    # Reverse Name Server.
    def reverse_nslookup(self, search_word):
        # Create target url.
        timestamp = self.timestamp()
        self.uri_reverse_nslookup = self.uri_reverse_nslookup.format(search_word)
        signature = self.sign(timestamp, self.uri_reverse_nslookup)
        target_url = 'https://{}{}?api_username={}&signature={}&timestamp={}'.format(self.api_host,
                                                                                     self.uri_reverse_nslookup,
                                                                                     self.api_username,
                                                                                     signature,
                                                                                     timestamp)

        # Send request.
        res, _, _, res_body, _ = self.utility.send_request('GET', target_url)
        if res is None or res.status >= 400:
            self.utility.print_message(FAIL, 'Could not access to {}.'.format(target_url))
            return []

        # Convert from string to dictionary.
        res_json = {}
        if 'application/json' in res.headers['Content-Type']:
            res_json = json.loads(res_body)
        else:
            self.utility.print_message(FAIL, 'Invalid Content-Type :{}.'.format(res.headers['Content-Type']))
            return []

        # Extract domain list.
        domain_list = []
        if 'domains' in res_json.keys():
            domain_list = res_json['domains']

        return domain_list

    # Whois lookup.
    def whois_lookup(self, domain):
        # Whois records.
        contact = []
        registrant_name = []
        registrant_organization = []
        registrant_email = []
        admin_name = []
        admin_organization = []
        admin_email = []
        tech_name = []
        tech_organization = []
        tech_email = []
        name_server = []

        # Create target url.
        self.uri_whois_lookup = self.uri_whois_lookup.format(domain)
        target_url = 'https://{}{}'.format(self.api_host, self.uri_whois_lookup)

        # Send request.
        res, _, _, res_body, _ = self.utility.send_request('GET', target_url)
        if res is None or res.status >= 400:
            self.utility.print_message(FAIL, 'Could not access to {}.'.format(target_url))
            return False, [], [], [], [], [], [], [], [], [], [], []

        # Convert from string to dictionary.
        res_json = {}
        if 'application/json' in res.headers['Content-Type']:
            res_json = json.loads(res_body)
        else:
            self.utility.print_message(FAIL, 'Invalid Content-Type :{}.'.format(res.headers['Content-Type']))
            return False, [], [], [], [], [], [], [], [], [], [], []

        # Get profitable information.
        if 'response' in res_json.keys():
            # Get name server.
            if 'name_servers' in res_json['response'].keys():
                name_server.extend(res_json['response']['name_servers'])

            # Check status.
            if len(name_server) == 0:
                self.utility.print_message(WARNING, 'Could not get whois record.')
                return False, [], [], [], [], [], [], [], [], [], [], []

            # Get whois record.
            if 'whois' in res_json['response'].keys() and 'record' in res_json['response']['whois'].keys():
                raw_record_list = re.split(r'[\r\n]', res_json['response']['whois']['record'])
                for record_item in raw_record_list:
                    items = record_item.split(': ')
                    # Administrative Contact.
                    if items[0].lower() == 'Administrative Contact'.lower():
                        contact.append(items[1])
                    # Technical Contact.
                    elif items[0].lower() == 'Technical Contact'.lower():
                        contact.append(items[1])
                    # Registrant Name.
                    elif items[0].lower() == 'Registrant Name'.lower():
                        registrant_name.append(items[1])
                    # Registrant Organization.
                    elif items[0].lower() == 'Registrant Organization'.lower():
                        registrant_organization.append(items[1])
                    # Registrant Email.
                    elif items[0].lower() == 'Registrant Email'.lower():
                        registrant_email.append(items[1])
                    # Admin Name.
                    elif items[0].lower() == 'Admin Name'.lower():
                        admin_name.append(items[1])
                    # Admin Organization.
                    elif items[0].lower() == 'Admin Organization'.lower():
                        admin_organization.append(items[1])
                    # Admin Email.
                    elif items[0].lower() == 'Admin Email'.lower():
                        admin_email.append(items[1])
                    # Tech Name.
                    elif items[0].lower() == 'Tech Name'.lower():
                        tech_name.append(items[1])
                    # Tech Organization.
                    elif items[0].lower() == 'Tech Organization'.lower():
                        tech_organization.append(items[1])
                    # Tech Email.
                    elif items[0].lower() == 'Tech Email'.lower():
                        tech_email.append(items[1])
        else:
            self.utility.print_message(WARNING, 'Could not get whois record.')
            return False, [], [], [], [], [], [], [], [], [], [], [], []

        # Delete duplication.
        contact = list(set(contact))
        registrant_name = list(set(registrant_name))
        registrant_organization = list(set(registrant_organization))
        registrant_email = list(set(registrant_email))
        admin_name = list(set(admin_name))
        admin_organization = list(set(admin_organization))
        admin_email = list(set(admin_email))
        tech_name = list(set(tech_name))
        tech_organization = list(set(tech_organization))
        tech_email = list(set(tech_email))
        name_server = list(set(name_server))

        return True, contact, registrant_name, registrant_organization, registrant_email, admin_name, \
               admin_organization, admin_email, tech_name, tech_organization, tech_email, name_server
