#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import configparser
import pickle
from .NaiveBayes import NaiveBayes

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class VersionCheckerML:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        try:
            config.read(os.path.join(self.root_path, 'config.ini'))
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

        self.category_type = config['VersionCheckerML']['category']
        self.train_path = os.path.join(self.full_path, config['VersionCheckerML']['train_path'])
        self.trained_path = os.path.join(self.full_path, config['VersionCheckerML']['trained_path'])
        self.train_os_in = os.path.join(self.train_path, config['VersionCheckerML']['train_os_in'])
        self.train_os_out = os.path.join(self.trained_path, config['VersionCheckerML']['train_os_out'])
        self.train_web_in = os.path.join(self.train_path, config['VersionCheckerML']['train_web_in'])
        self.train_web_out = os.path.join(self.trained_path, config['VersionCheckerML']['train_web_out'])
        self.train_framework_in = os.path.join(self.train_path, config['VersionCheckerML']['train_framework_in'])
        self.train_framework_out = os.path.join(self.trained_path, config['VersionCheckerML']['train_framework_out'])
        self.train_cms_in = os.path.join(self.train_path, config['VersionCheckerML']['train_cms_in'])
        self.train_cms_out = os.path.join(self.trained_path, config['VersionCheckerML']['train_cms_out'])
        return

        # Identify product name using ML.
    def identify_product(self, response):
        self.utility.write_log(20, '[In] Identify product [{}].'.format(self.file_name))
        product_list = []

        try:
            # Predict product name each category (OS, Middleware, CMS..).
            list_category = self.category_type.split('@')
            for category in list_category:
                # Learning.
                nb = None
                if category == 'OS':
                    nb = self.train(self.train_os_in, self.train_os_out)
                elif category == 'WEB':
                    nb = self.train(self.train_web_in, self.train_web_out)
                elif category == 'FRAMEWORK':
                    nb = self.train(self.train_framework_in, self.train_framework_out)
                elif category == 'CMS':
                    nb = self.train(self.train_cms_in, self.train_cms_out)
                else:
                    self.utility.print_message(FAIL, 'Choose category is not found.')
                    exit(1)

                # Predict product name.
                product, prob, keyword_list, classified_list = nb.classify(response)

                # Output result of prediction (body).
                # If no feature, result is unknown.
                if len(keyword_list) != 0:
                    product_list.append([category, '*', product, '*', ','.join(keyword_list)])
                    msg = 'Predict product={}/{}%, verson={}, trigger={}'.format(product, prob, '*', keyword_list)
                    self.utility.print_message(OK, msg)
                    self.utility.write_log(20, msg)
                    self.utility.print_message(NOTE, 'category : {}'.format(category))
        except Exception as e:
            msg = 'Identifying product is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)

        self.utility.write_log(20, '[Out] Identify product [{}].'.format(self.file_name))
        return list(map(list, set(map(tuple, product_list))))

    # Classifier product name using Machine Learning.
    def get_product_name(self, response):
        self.utility.print_message(NOTE, 'Analyzing gathered HTTP response using ML.')
        self.utility.write_log(20, '[In] Analyzing gathered HTTP response [{}].'.format(self.file_name))

        # Execute classifier.
        product_list = self.identify_product(response)
        if len(product_list) == 0:
            self.utility.print_message(WARNING, 'Product Not Found.')
            self.utility.write_log(30, 'Product Not Found.')

        self.utility.write_log(20, '[Out] Analyzing gathered HTTP response [{}].'.format(self.file_name))
        return product_list

    # Execute learning / Get learned data.
    def train(self, in_file, out_file):
        self.utility.write_log(20, '[In] Train/Get learned data [{}].'.format(self.file_name))
        # If existing learned data (pkl), load learned data.
        nb = None
        if os.path.exists(out_file):
            with open(out_file, 'rb') as f:
                nb = pickle.load(f)
        # If no learned data, execute learning.
        else:
            # Read learning data.
            nb = NaiveBayes()
            with codecs.open(in_file, 'r', 'utf-8') as fin:
                lines = fin.readlines()
                items = []

                for line in lines:
                    words = line[:-2]
                    train_words = words.split('@')
                    items.append(train_words[1])
                    nb.train(train_words[3], train_words[0])

            # Save learned data to pkl file.
            with open(out_file, 'wb') as f:
                pickle.dump(nb, f)
        self.utility.write_log(20, '[Out] Train/Get learned data [{}].'.format(self.file_name))
        return nb
