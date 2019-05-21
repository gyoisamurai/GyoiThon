#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import re
import json
import ipaddress
import subprocess
import configparser
from bs4 import BeautifulSoup

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class CloudChecker:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.aws_srv_name = config['CloudChecker']['aws_srv_name']
            self.aws_ip_range = config['CloudChecker']['aws_ip_range']
            self.azure_srv_name = config['CloudChecker']['azure_srv_name']
            self.azure_ip_range = config['CloudChecker']['azure_ip_range']
            self.gcp_srv_name = config['CloudChecker']['gcp_srv_name']
            self.gcp_nslookup_cmd = config['CloudChecker']['gcp_nslookup_cmd']
            self.gcp_content_srv = config['CloudChecker']['gcp_content_srv']
            self.gcp_content_ip = config['CloudChecker']['gcp_content_ip']
            self.gcp_get_domain_regex = config['CloudChecker']['gcp_get_domain_regex']
            self.gcp_get_nwaddr_regex = config['CloudChecker']['gcp_get_nwaddr_regex']
            self.action_name = 'Cloud Checker'
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Check AWS.
    def check_aws(self, ip_addr):
        self.utility.print_message(NOTE, 'Check AWS IP range.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check AWS IP range.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Get IP range list.
        self.utility.write_log(20, 'Accessing : {}'.format(self.aws_ip_range))
        res, _, _, _, encoding = self.utility.send_request('GET', self.aws_ip_range)
        aws_nw_addres = json.loads(res.data.decode(encoding))['prefixes']

        # Check all aws ip_address.
        target_ip = ipaddress.ip_address(ip_addr)
        for aws_nw_addr in aws_nw_addres:
            if target_ip in ipaddress.ip_network(aws_nw_addr['ip_prefix']):
                msg = 'Detect : service=AWS target={} prefix={} region={} service={}'.format(target_ip,
                                                                                             aws_nw_addr['ip_prefix'],
                                                                                             aws_nw_addr['region'],
                                                                                             aws_nw_addr['service'])
                self.utility.print_message(OK, msg)
                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note=msg,
                                                dest=self.utility.target_host)
                self.utility.write_log(20, msg)
                msg = self.utility.make_log_msg(self.utility.log_out,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note='[Out] Check AWS IP range.',
                                                dest=self.utility.target_host)
                self.utility.write_log(20, msg)
                return True
            else:
                self.utility.print_message(FAIL, 'Not include : service=AWS target={} prefix={}'
                                           .format(target_ip, aws_nw_addr['ip_prefix']))

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='[Out] Check AWS IP range.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return False

    # Check Azure.
    def check_azure(self, ip_addr):
        self.utility.print_message(NOTE, 'Check Azure IP range.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check Azure IP range.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Get IP range list.
        self.utility.write_log(20, 'Accessing : {}'.format(self.azure_ip_range))
        res, _, _, _, encoding = self.utility.send_request('GET', self.azure_ip_range)
        soup = BeautifulSoup(res.data.decode(encoding).lower(), 'lxml')
        regions = soup.find_all('region')

        # Check all azure ip_address.
        target_ip = ipaddress.ip_address(ip_addr)
        for idx, region in enumerate(regions):
            azure_nw_addres = []
            region_name = region.attrs['name']
            for content in region.contents:
                if content.name == 'iprange':
                    azure_nw_addres.append(content['subnet'])

            for azure_nw_addr in azure_nw_addres:
                if target_ip in ipaddress.ip_network(azure_nw_addr):
                    msg = 'Detect : service=Azure target={} prefix={} region={}'.format(target_ip, azure_nw_addr, region_name)
                    self.utility.print_message(OK, msg)
                    msg = self.utility.make_log_msg(self.utility.log_mid,
                                                    self.utility.log_dis,
                                                    self.file_name,
                                                    action=self.action_name,
                                                    note=msg,
                                                    dest=self.utility.target_host)
                    self.utility.write_log(20, msg)
                    msg = self.utility.make_log_msg(self.utility.log_out,
                                                    self.utility.log_dis,
                                                    self.file_name,
                                                    action=self.action_name,
                                                    note='Check Azure IP range',
                                                    dest=self.utility.target_host)
                    self.utility.write_log(20, msg)
                    return True
                else:
                    self.utility.print_message(FAIL, 'Not include : service=Azure target={} prefix={}'
                                               .format(target_ip, azure_nw_addr))

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check Azure IP range',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return False

    # Check GCP.
    def check_gcp(self, ip_addr):
        self.utility.print_message(NOTE, 'Check GCP IP range.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check GCP IP range',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Get Domain in SPF record using nslookup command.
        raw_domains = ''
        nslookup_cmd = self.gcp_nslookup_cmd + ' ' + self.gcp_content_srv + ' ' + self.gcp_content_ip
        try:
            msg = self.utility.make_log_msg(self.utility.log_mid,
                                            self.utility.log_dis,
                                            self.file_name,
                                            action=self.action_name,
                                            note='Execute : {}'.format(nslookup_cmd),
                                            dest=self.utility.target_host)
            self.utility.write_log(20, msg)
            raw_domains = subprocess.check_output(nslookup_cmd, shell=True)
        except Exception as e:
            msg = 'Executing {} is failure.'.format(nslookup_cmd)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)
            self.utility.write_log(20, '[Out] Check GCP IP range [{}].'.format(self.file_name))
            return False

        # Set character code.
        char_code = ''
        if os.name == 'nt':
            char_code = 'shift-jis'
        else:
            char_code = 'utf-8'

        # Get Network addresses from each domain.
        gcp_domain_list = re.findall(self.gcp_get_domain_regex, raw_domains.decode(char_code))
        gcp_nw_addres = []
        for gcp_domain in gcp_domain_list:
            nslookup_cmd = self.gcp_nslookup_cmd + ' ' + gcp_domain + ' ' + self.gcp_content_ip
            try:
                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note='Execute : {}'.format(nslookup_cmd),
                                                dest=self.utility.target_host)
                self.utility.write_log(20, msg)
                raw_ip = subprocess.check_output(nslookup_cmd, shell=True)
            except Exception as e:
                msg = 'Executing {} is failure.'.format(nslookup_cmd)
                self.utility.print_exception(e, msg)
                self.utility.write_log(30, msg)
                continue

            gcp_nwaddres_from_one_domain = re.findall(self.gcp_get_nwaddr_regex, raw_ip.decode(char_code))
            for nwaddr in gcp_nwaddres_from_one_domain:
                gcp_nw_addres.append(nwaddr)

        # Check all gcp ip_address.
        target_ip = ipaddress.ip_address(ip_addr)
        for gcp_nw_addr in gcp_nw_addres:
            if target_ip in ipaddress.ip_network(gcp_nw_addr):
                msg = 'Detect : service=GCP target={} prefix={}'.format(target_ip, gcp_nw_addr)
                self.utility.print_message(OK, msg)
                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note=msg,
                                                dest=self.utility.target_host)
                self.utility.write_log(20, msg)
                msg = self.utility.make_log_msg(self.utility.log_out,
                                                self.utility.log_dis,
                                                self.file_name,
                                                action=self.action_name,
                                                note='Check GCP IP range',
                                                dest=self.utility.target_host)
                self.utility.write_log(20, msg)
                return True
            else:
                self.utility.print_message(FAIL, 'Not include : service=GCP target={} prefix={}'
                                           .format(target_ip, gcp_nw_addr))

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check GCP IP range.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        return False

    # Identify cloud service name.
    def get_cloud_service(self, fqdn):
        self.utility.print_message(NOTE, 'Analyze cloud service.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Analyze cloud service.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        target_ip = self.utility.forward_lookup(fqdn)

        # Check cloud service name.
        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Analyze cloud service.',
                                        dest=self.utility.target_host)
        if self.check_aws(target_ip) is True:
            self.utility.write_log(20, msg)
            return self.aws_srv_name
        elif self.check_azure(target_ip) is True:
            self.utility.write_log(20, msg)
            return self.azure_srv_name
        elif self.check_gcp(target_ip) is True:
            self.utility.write_log(20, msg)
            return self.gcp_srv_name
        else:
            self.utility.write_log(20, msg)
            return 'Unknown'
