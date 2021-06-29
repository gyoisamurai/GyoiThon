#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import time
import json
import copy
import re
import glob
import tldextract
import subprocess
import configparser
import pandas as pd

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.

# Confidential score.
HIGH = 2
MEDIUM = 1
LOW = 0


class Inventory:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'), encoding='utf-8')

        try:
            self.signature_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.tmp_inventory_dir = os.path.join(self.root_path, config['Inventory']['tmp_inventory_dir'])
            if os.path.exists(self.tmp_inventory_dir) is False:
                os.mkdir(self.tmp_inventory_dir)
            self.black_list_path = os.path.join(self.signature_dir, config['Inventory']['black_list'])
            self.black_list = []
            if os.path.exists(self.black_list_path) is False:
                self.black_list = []
            else:
                with codecs.open(self.black_list_path, 'r', encoding='utf-8') as fin:
                    self.black_list = fin.readlines()
            self.max_search_num = int(config['Inventory']['max_search_num'])
            self.jprs_url = config['Inventory']['jprs_url']
            self.jprs_post = {'type': '', 'key': ''}
            self.jprs_regex_multi = config['Inventory']['jprs_regex_multi']
            self.jprs_regex_single = config['Inventory']['jprs_regex_single'].split('@')
            self.jprs_contact_path = config['Inventory']['jprs_contact_path']
            self.jprs_regex_org = config['Inventory']['jprs_regex_org']
            self.jprs_regex_mail = config['Inventory']['jprs_regex_mail'].split('@')
            self.jpnic_url = config['Inventory']['jpnic_url']
            self.jpnic_post = {'codecheck-sjis': 'にほんねっとわーくいんふぉめーしょんせんたー',
                               'key': '', 'submit': '検索', 'type': 'NET-HOLDER', 'rule': ''}
            self.jpnic_regex_multi = config['Inventory']['jpnic_regex_multi']
            self.jpnic_regex_single = config['Inventory']['jpnic_regex_single']
            self.nslookup_delay_time = float(config['Inventory']['nslookup_delay_time'])
            self.nslookup_cmd = config['Inventory']['nslookup_cmd']
            self.nslookup_options = config['Inventory']['nslookup_options'].split('@')
            self.nslookup_regex_ip = config['Inventory']['nslookup_regex_ip'].split('@')
            self.cname_regex = config['Inventory']['cname_regex'].split('@')
            self.mx_rec_regex = config['Inventory']['mx_rec_regex'].split('@')
            self.mx_rec_regex_multi = config['Inventory']['mx_rec_regex_multi'].split('@')
            self.ns_rec_regex = config['Inventory']['ns_rec_regex'].split('@')
            self.soa_rec_regex = config['Inventory']['soa_rec_regex'].split('@')
            self.txt_rec_regex = config['Inventory']['txt_rec_regex'].split('@')
            self.action_name = 'Search FQDN'

            # Set character code.
            self.char_code = ''
            self.os_index = 0
            if os.name == 'nt':
                self.char_code = 'shift-jis'
            else:
                self.char_code = 'utf-8'
                self.os_index = 1
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Execute nslookup command.
    def execute_nslookup(self, domain, option):
        self.utility.write_log(20, '[In] Execute nslookup command [{}].'.format(self.file_name))

        # Execute nslookup command.
        nslookup_result = ''
        nslookup_cmd = self.nslookup_cmd + option + ' ' + domain
        try:
            self.utility.write_log(20, 'Execute : {}'.format(nslookup_cmd))
            nslookup_result = subprocess.check_output(nslookup_cmd, shell=True)
            self.utility.print_message(OK, 'Execute : {}'.format(nslookup_cmd))
        except Exception as e:
            msg = 'Executing {} is failure.'.format(nslookup_cmd)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)

        self.utility.write_log(20, '[Out] Execute nslookup command [{}].'.format(self.file_name))
        return nslookup_result

    # Explore DNS information.
    def dns_explore(self, domain):
        self.utility.print_message(NOTE, 'Explore FQDN using DNS server.')
        self.utility.write_log(20, '[In] Explore FQDN using DNS server [{}].'.format(self.file_name))

        # Get DNS  addresses from each domain.
        dns_info = {'A': 'N/A', 'CNAME': 'N/A', 'NS': 'N/A', 'MX': 'N/A', 'SOA': 'N/A', 'TXT': 'N/A'}
        ip_adder = 'N/A'
        for option in self.nslookup_options:
            nslookup_result = self.execute_nslookup(domain, option)
            if nslookup_result != '':
                nslookup_result = nslookup_result.decode(self.char_code)
                if option == 'A':
                    ip_adder = re.findall(self.nslookup_regex_ip[self.os_index], nslookup_result)
                dns_info[option] = nslookup_result
            else:
                self.utility.print_message(WARNING, 'Executing nslookup is failure : option={}.'.format(option))
                break

            time.sleep(self.nslookup_delay_time)

        self.utility.write_log(20, '[Out] Explore FQDN using DNS server [{}].'.format(self.file_name))
        return ip_adder, dns_info

    # Get profitable information from JPRS.
    def domain_explore_jprs(self, contact_list):
        self.utility.print_message(NOTE, 'Get profitable information using JPRS.')
        self.utility.write_log(20, '[In] Get profitable information using JPRS. [{}].'.format(self.file_name))

        # Send request for gathering profitable information.
        organization_list = []
        email_list = []
        for contact in contact_list:
            self.jprs_post['type'] = 'POC'
            self.jprs_post['key'] = contact
            res, _, _, res_body, _ = self.utility.send_request('POST',
                                                               self.jprs_url + self.jprs_contact_path,
                                                               body_param=self.jprs_post,
                                                               cert_ignore=True)
            if res is None or res.status >= 400:
                self.utility.print_message(FAIL, 'Could not access to {}.'.format(self.jprs_url+self.jprs_contact_path))
            else:
                # Extract Organization.
                organization_list.extend(re.findall(self.jprs_regex_org, res_body))
                if len(organization_list) != 0:
                    self.utility.print_message(NOTE, 'Gathered Organization from JPRS. : {}'.format(organization_list))
                else:
                    self.utility.print_message(WARNING, 'Could not gather Organization from JPRS.')

                # Extract Email.
                for regex_email in self.jprs_regex_mail:
                    email_list.extend(re.findall(regex_email, res_body))
                if len(email_list) != 0:
                    self.utility.print_message(NOTE, 'Gathered Email from JPRS. : {}'.format(email_list))
                else:
                    self.utility.print_message(WARNING, 'Could not gather Email from JPRS.')

        self.utility.write_log(20, '[Out] Get profitable information using JPRS. [{}].'.format(self.file_name))
        return list(set(organization_list)), list(set(email_list))

    # Mutate domain.
    def mutated_domain(self, origin_domain):
        self.utility.print_message(NOTE, 'Mutate domain.')
        self.utility.write_log(20, '[In] Mutate domain [{}].'.format(self.file_name))

        # Mutate domain.
        mutation_domain_list = []
        ext = tldextract.extract(origin_domain)
        mutation_domain_list.append(ext.domain + '.com')
        mutation_domain_list.append(ext.domain + '.jp')
        mutation_domain_list.append(ext.domain + '.co.jp')
        mutation_domain_list.append(ext.domain + '.net')
        mutation_domain_list.append(ext.domain + '.ne.jp')
        mutation_domain_list.append(ext.domain + '.org')
        mutation_domain_list.append(ext.domain + '.or.jp')

        self.utility.write_log(20, '[Out] Mutate domain [{}].'.format(self.file_name))
        return list(set([s for s in mutation_domain_list if origin_domain != s]))

    # Check existing temporary Json file for domain.
    def check_existing_tmp_json(self, domain):
        self.utility.print_message(NOTE, 'Check existing temporary Json file for domain.')
        self.utility.write_log(20, '[In] Check existing temporary Json file for domain. [{}].'.format(self.file_name))

        self.utility.print_message(OK, 'Check existing temporary Json file for "{}".'.format(domain))

        self.utility.write_log(20, '[In] Check existing temporary Json file for domain. [{}].'.format(self.file_name))
        return os.path.exists(os.path.join(self.tmp_inventory_dir, domain))

    # Extract whois information.
    def extract_whois_info(self, dt, domain_list, origin_domain='-', mutation=False, import_list=False, organization_id='N/A', domain_id='N/A'):
        self.utility.print_message(NOTE, 'Extract whois information.')
        self.utility.write_log(20, '[In] Extract whois information. [{}].'.format(self.file_name))

        # Whois lookup using DomainTools.
        domain_info_dict = {}
        for domain in domain_list:
            # Domain Structure.
            if type(domain) == list:
                if len(domain) == 3:
                    organization_id = domain[0]
                    domain_id = domain[1]
                    domain = domain[2]
                else:
                    self.utility.print_message(WARNING, 'Invalid domain list. Length is "{}".'.format(len(domain)))
                    continue

            domain_basic = {'Organization ID': organization_id, 'Domain ID': domain_id,
                            'IP Address': '', 'Date': '', 'Mutation': '', 'Origin Domain': '',
                            'Whois': {}, 'DNS': {}, 'Sub-domain': {}, 'Note': ''}
            domain_whois = {'Contact': 'N/A', 'Registrant Name': 'N/A', 'Registrant Organization': 'N/A',
                            'Registrant Email': 'N/A', 'Admin Name': 'N/A', 'Admin Organization': 'N/A',
                            'Admin Email': 'N/A', 'Tech Name': 'N/A', 'Tech Organization': 'N/A', 'Tech Email': 'N/A',
                            'Name Server': 'N/A'}

            if self.check_existing_tmp_json(domain):
                self.utility.print_message(WARNING, 'Existing temporary Json file for "{}".'.format(domain))
                domain_info_dict[domain] = domain_basic
                continue

            # Set basic records.
            domain_basic['Date'] = self.utility.get_current_date()
            domain_basic['Mutation'] = mutation
            domain_basic['Origin Domain'] = origin_domain

            # Get whois record.
            if import_list is False:
                status, contact, registrant_name, registrant_organization, registrant_email, admin_name, \
                admin_organization, admin_email, tech_name, tech_organization, tech_email, \
                name_server = dt.whois_lookup(domain)

                # Set whois records.
                if status is False:
                    domain_basic['Whois'] = domain_whois
                else:
                    domain_whois['Contact'] = contact.extend(contact)
                    domain_whois['Registrant Name'] = registrant_name.extend(registrant_name)
                    domain_whois['Registrant Organization'] = registrant_organization.extend(registrant_organization)
                    domain_whois['Registrant Email'] = registrant_email.extend(registrant_email)
                    domain_whois['Admin Name'] = admin_name.extend(admin_name)
                    domain_whois['Admin Organization'] = admin_organization.extend(admin_organization)
                    domain_whois['Admin Email'] = admin_email.extend(admin_email)
                    domain_whois['Tech Name'] = tech_name.extend(tech_name)
                    domain_whois['Tech Organization'] = tech_organization.extend(tech_organization)
                    domain_whois['Tech Email'] = tech_email.extend(tech_email)
                    domain_whois['Name Server'] = name_server.extend(name_server)
                    domain_basic['Whois'] = domain_whois

                domain_info_dict[domain] = domain_basic
            else:
                domain_basic['Whois'] = domain_whois
                domain_info_dict[domain] = domain_basic

        self.utility.write_log(20, '[Out] Extract whois information. [{}].'.format(self.file_name))
        return domain_info_dict

    # Extract domain from import list.
    def extract_domain_from_list(self, import_list_path):
        domain_list = []
        df = pd.read_csv(import_list_path, encoding='utf-8')
        if len(df.columns) == 1:
            domain_list = df.loc[:, 'Domain Name'].values.tolist()
            domain_list = sorted(set(domain_list), key=domain_list.index)
        elif len(df.columns) == 3:
            domain_list = df.values.tolist()
            domain_list = sorted(list(map(list, set(map(tuple, domain_list)))), key=lambda i: domain_list.index(i))
        else:
            self.utility.print_message(WARNING, 'Invalid domain list: "{}".'.format(import_list_path))
        return domain_list

    # Explore domain.
    def domain_explore(self, dt=None, search_word=None, search_type=None, import_list=None):
        self.utility.print_message(NOTE, 'Explore domain.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Explore domain.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Get domain list.
        domain_list = []
        import_list_flag = False
        if search_type in ['Organization', 'Email'] and dt is not None:
            domain_list = dt.reverse_whois(search_word)
        elif search_type == 'NS' and dt is not None:
            domain_list = dt.reverse_nslookup(search_word)
        elif import_list is not None:
            import_list_flag = True
            domain_list = self.extract_domain_from_list(import_list)
        else:
            self.utility.print_message(FAIL, 'Search type is None.')
            return {}

        # Get whois information for normal domain.
        domain_info_dict = self.extract_whois_info(dt, domain_list, import_list=import_list_flag)

        # Get whois information for mutated domain.
        tmp_domain_info = copy.deepcopy(domain_info_dict)
        for idx, domain in enumerate(tmp_domain_info.keys()):
            self.utility.print_message(OK, '[{}/{}] Mutation of "{}"'.format(idx + 1, len(tmp_domain_info), domain))
            mutated_domain_list = self.mutated_domain(domain)
            mutated_domain_info_dict = self.extract_whois_info(dt,
                                                               mutated_domain_list,
                                                               origin_domain=domain,
                                                               mutation=True,
                                                               import_list=import_list_flag,
                                                               organization_id=tmp_domain_info[domain]['Organization ID'],
                                                               domain_id=tmp_domain_info[domain]['Domain ID'])
            domain_info_dict.update(mutated_domain_info_dict)
            self.utility.print_message(OK, 'Mutated : "{}" to "{}"'.format(domain, mutated_domain_list))

        # Get domain list from JPRS.
        for idx, domain in enumerate(domain_info_dict.keys()):
            self.utility.print_message(OK, '[{}/{}] JPRS Search of "{}"'.format(idx + 1, len(domain_info_dict), domain))
            if self.check_existing_tmp_json(domain):
                self.utility.print_message(WARNING, 'Existing temporary Json file for "{}".'.format(domain))
                continue

            if type(domain_info_dict[domain]['Whois']['Contact']) == list:
                organization_list, email_list = self.domain_explore_jprs(domain_info_dict[domain]['Whois']['Contact'])

                # Merge Registrant Organization and Email.
                if len(organization_list) != 0:
                    origin_organization_list = domain_info_dict[domain]['Whois']['Registrant Organization']
                    origin_organization_list.extend(organization_list)
                    domain_info_dict[domain]['Whois']['Registrant Organization'] = list(set(origin_organization_list))
                if len(email_list) != 0:
                    origin_email_list = domain_info_dict[domain]['Whois']['Registrant Email']
                    origin_email_list.extend(email_list)
                    domain_info_dict[domain]['Whois']['Registrant Email'] = list(set(origin_email_list))
            else:
                self.utility.print_message(OK, 'Contact is None')

        # Get DNS record information.
        for idx, domain in enumerate(domain_info_dict.keys()):
            self.utility.print_message(OK, '[{}/{}] DNS search of "{}"'.format(idx + 1, len(domain_info_dict), domain))
            if self.check_existing_tmp_json(domain):
                self.utility.print_message(WARNING, 'Existing temporary Json file for "{}".'.format(domain))
                continue

            ip_address, dns_info = self.dns_explore(domain)
            domain_info_dict[domain]['IP Address'] = ip_address
            domain_info_dict[domain]['DNS'] = dns_info

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Explore domain.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return domain_info_dict

    # Get DNS record and IP address of sub-domain.
    def get_sub_domain_dns_record(self, sub_domain):
        self.utility.print_message(NOTE, 'Extract DNS record of sub-domain.')

        # Get DNS records of sub-domain.
        sub_domain_basic = {'IP Address': 'N/A',
                            'DNS': '',
                            'Access Status (http)': 'Not Access.',
                            'Location (http)': 'N/A',
                            'Access Status (https)': 'Not Access.',
                            'Location (https)': 'N/A'}
        ip_address, dns_info = self.dns_explore(sub_domain)
        sub_domain_basic['IP Address'] = ip_address
        sub_domain_basic['DNS'] = dns_info
        if ip_address != '':
            # Send request.
            for scheme, port in zip(['http', 'https'], ['80', '443']):
                target_url = '{}://{}:{}'.format(scheme, sub_domain, port)
                self.utility.print_message(OK, 'Send request to "{}".'.format(target_url))
                res, _, res_header, _, _ = self.utility.send_request('GET', target_url, cert_ignore=True)
                if res is not None:
                    # Set status code.
                    if scheme == 'http':
                        sub_domain_basic['Access Status (http)'] = res.status
                    else:
                        sub_domain_basic['Access Status (https)'] = res.status

                    # Set location header value.
                    if 300 <= res.status < 400:
                        location = ''
                        for header in res_header.split('\r\n'):
                            if header[:10].lower() == 'location: ':
                                location = header.split(': ')[1]
                                if scheme == 'http':
                                    sub_domain_basic['Location (http)'] = location
                                else:
                                    sub_domain_basic['Location (https)'] = location
                                break
                        self.utility.print_message(OK, 'Return status : {}, Location : {}.'.format(res.status, location))
                    else:
                        self.utility.print_message(OK, 'Return status : {}.'.format(res.status))
                else:
                    self.utility.print_message(FAIL, 'Could not access to {}.'.format(target_url))

        return sub_domain_basic

    # Explore sub-domain.
    def sub_domain_explore(self, domain_info_dict, google_hack):
        self.utility.print_message(NOTE, 'Explore sub-domain.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Explore sub-domain.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Get whois information for mutated domain.
        for idx, domain in enumerate(domain_info_dict.keys()):
            self.utility.print_message(OK, '[{}/{}] Sub-domain Explore of "{}"'.format(idx + 1, len(domain_info_dict), domain))
            if self.check_existing_tmp_json(domain):
                self.utility.print_message(WARNING, 'Existing temporary Json file for "{}".'.format(domain))
                continue

            # Add domain to sub-domain list.
            sub_domain_info_dict = {}
            sub_domain_info_dict[domain] = {'IP Address': domain_info_dict[domain]['IP Address'],
                                            'DNS': domain_info_dict[domain]['DNS'],
                                            'Access Status': 'N/A'}

            # Explore sub-domain using Google Custom Search.
            sub_domain_list, query = google_hack.search_domain(domain, max_search_num=self.max_search_num)
            sub_domain_list.append(domain)
            sub_domain_list.append('www.' + domain)
            for sub_idx, sub_domain in enumerate(list(set(sub_domain_list))):
                self.utility.print_message(OK, 'Search "{}"'.format(sub_domain))
                # Get DNS record and IP address of sub-domain.
                sub_domain_info = self.get_sub_domain_dns_record(sub_domain)
                sub_domain_info_dict[sub_domain] = sub_domain_info

            # Add sub-domain information to domain dict.
            domain_info_dict[domain]['Sub-domain'] = sub_domain_info_dict
            domain_info_dict[domain]['Note'] = query

            # Save domain information to temporary json file.
            with codecs.open(os.path.join(self.tmp_inventory_dir, domain), 'w', 'utf-8') as fout:
                json.dump(domain_info_dict[domain], fout, indent=4)

    # Extract target host of health check.
    def extract_host_info(self, report_path, report_header, safety, domain_list_path):
        self.utility.print_message(NOTE, 'Extract target host for health check.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Extract target host for health check.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Read inventory's report.
        df_invent = pd.read_csv(report_path, dtype=str, names=report_header)
        df_invent = df_invent.fillna('N/A')

        # Select target host.
        df_selected_http = df_invent[(df_invent['Sub-Domain'] != 'N/A') &
                                     (df_invent['Access Status (http)'] != 'Not Access.') &
                                     (df_invent['Access Status (http)'] != 'N/A')]
        df_selected_https = df_invent[(df_invent['Sub-Domain'] != 'N/A') &
                                      (df_invent['Access Status (https)'] != 'Not Access.') &
                                      (df_invent['Access Status (https)'] != 'N/A')]

        protocol_list = []
        fqdn_list = []
        port_list = []
        path_list = []
        target_domain_list = []
        for target_domain in self.extract_domain_from_list(domain_list_path):
            if type(target_domain) == list:
                if len(target_domain) == 3:
                    target_domain_list.append(target_domain[2])
                else:
                    self.utility.print_message(WARNING, 'Invalid domain list. Length is "{}".'.format(len(target_domain)))
                    break
            elif type(target_domain) == str:
                target_domain_list.append(target_domain)

        # Select target's subdomain (http).
        for idx, subdomain in enumerate(df_selected_http['Sub-Domain'].drop_duplicates()):
            if idx == 0:
                continue
            # Exclude out of target domain.
            if safety:
                ext = tldextract.extract(subdomain)
                if ext.domain + '.' + ext.suffix not in target_domain_list:
                    continue
            protocol_list.append('http')
            fqdn_list.append(subdomain)
            port_list.append('80')
            path_list.append('/')

        # Select target's subdomain (https).
        for idx, subdomain in enumerate(df_selected_https['Sub-Domain'].drop_duplicates()):
            if idx == 0:
                continue

            # Exclude out of target domain.
            if safety:
                ext = tldextract.extract(subdomain)
                if ext.domain + '.' + ext.suffix not in target_domain_list:
                    continue
            protocol_list.append('https')
            fqdn_list.append(subdomain)
            port_list.append('443')
            path_list.append('/')

        return protocol_list, fqdn_list, port_list, path_list

    # Update inventory to gyoiboard.
    def push_result_to_gyoiboard(self, tmp_inventory_dir):
        # Gather reporting items.
        json_file_list = glob.glob(os.path.join(tmp_inventory_dir, '*'))

        # Build base structure.
        report = []
        index = 1
        for json_file_path in json_file_list:
            domain_info = {}
            with codecs.open(json_file_path, 'r', 'utf-8') as fin:
                domain_info = json.load(fin)
