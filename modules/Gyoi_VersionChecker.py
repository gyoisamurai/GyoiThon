#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import re
import configparser

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class VersionChecker:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.signatures_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.signature_file = os.path.join(self.signatures_dir, config['VersionChecker']['signature_file'])
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Identify product name using signature.
    def identify_product(self, response):
        self.utility.write_log(20, '[In] Identify product [{}].'.format(self.file_name))
        product_list = []

        try:
            # Identify product name and version.
            with codecs.open(self.signature_file, 'r', 'utf-8') as fin:
                matching_patterns = fin.readlines()
                for pattern in matching_patterns:
                    items = pattern.replace('\r', '').replace('\n', '').split('@')
                    category = items[0]
                    vendor = items[1].lower()
                    product = items[2].lower()
                    default_ver = items[3]
                    signature = items[4]
                    obj_match = re.search(signature, response, flags=re.IGNORECASE)
                    if obj_match is not None:
                        trigger = obj_match.group(1)

                        # Check version.
                        version = default_ver
                        if obj_match.re.groups > 1:
                            version = obj_match.group(2)

                        # Add product name and version.
                        product_list.append([category, vendor, product, version, trigger])
                        msg = 'Find product={}/{}, verson={}, trigger={}'.format(vendor, product, version, trigger)
                        self.utility.print_message(OK, msg)
                        self.utility.write_log(20, msg)
        except Exception as e:
            msg = 'Identifying product is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)

        self.utility.write_log(20, '[Out] Identify product [{}].'.format(self.file_name))
        return list(map(list, set(map(tuple, product_list))))

    # Classifier product name using signatures.
    def get_product_name(self, response):
        self.utility.print_message(NOTE, 'Analyzing gathered HTTP response.')
        self.utility.write_log(20, '[In] Analyzing gathered HTTP response [{}].'.format(self.file_name))

        # Execute classifier.
        product_list = self.identify_product(response)
        if len(product_list) == 0:
            self.utility.print_message(WARNING, 'Product Not Found.')
            self.utility.write_log(30, 'Product Not Found.')

        self.utility.write_log(20, '[Out] Analyzing gathered HTTP response [{}].'.format(self.file_name))
        return product_list
