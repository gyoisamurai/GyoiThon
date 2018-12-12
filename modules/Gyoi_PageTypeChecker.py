#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import re
import configparser
import pickle
from .NaiveBayes import NaiveBayes

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class PageChecker:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.train_path = os.path.join(self.full_path, config['PageChecker']['train_path'])
            self.train_file = os.path.join(self.train_path, config['PageChecker']['train_page'])
            self.trained_path = os.path.join(self.full_path, config['PageChecker']['trained_path'])
            self.trained_file = os.path.join(self.trained_path, config['PageChecker']['trained_page'])
            self.signatures_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.signature_file = os.path.join(self.signatures_dir, config['PageChecker']['signature_file'])
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Judge page type.
    def judge_page_type(self, target_url, response):
        self.utility.print_message(NOTE, 'Judge page type.')
        self.utility.write_log(20, '[In] Judge page type [{}].'.format(self.file_name))
        # page_type = {'ml': {'type': 'unknown', 'reason': '-'}, 'url': {'type': 'unknown', 'reason': '-'}}
        page_type = {'ml': {'prob': '-', 'reason': '-'}, 'url': {'prob': '-', 'reason': '-'}}

        # Learning.
        nb = self.train(self.train_file, self.trained_file)
        if nb is None:
            self.utility.write_log(20, '[Out] Judge page type [{}].'.format(self.file_name))
            return 'unknown'

        # Predict page type using Naive Bayes.
        self.utility.print_message(OK, 'Predict page type.')
        predict_result, prob, keywords, classified_list = nb.classify(response)
        if len(keywords) == 0:
            self.utility.print_message(OK, 'Page type is unknown.')
        else:
            page_type['ml']['prob'] = str(round(prob*100, 2))
            page_type['ml']['reason'] = ','.join(keywords)
            msg = 'ML: Page type={}/{}%, reason={}'.format(predict_result,
                                                           round(prob*100, 2),
                                                           page_type['ml']['reason'])
            self.utility.print_message(OK, msg)
            self.utility.write_log(20, msg)

        # Predict Basic Authenticate.
        predict_result, page_type['url']['prob'], page_type['url']['reason'] = self.predict_basic_auth(response)
        msg = 'URL: Page type={}/{}%, reason={}'.format(predict_result,
                                                        page_type['url']['prob'],
                                                        page_type['url']['reason'])
        self.utility.print_message(OK, msg)
        self.utility.write_log(20, msg)

        if page_type['url']['prob'] != '100.0':
            # Predict page type using URL.
            predict_result, page_type['url']['prob'], page_type['url']['reason'] = self.predict_page_type(target_url)
            msg = 'URL: Page type={}/{}%, reason={}'.format(predict_result,
                                                            page_type['url']['prob'],
                                                            page_type['url']['reason'])
            self.utility.print_message(OK, msg)
            self.utility.write_log(20, msg)

        self.utility.write_log(20, '[Out] Judge page type [{}].'.format(self.file_name))
        return page_type

    # Predict page type using URL.
    def predict_page_type(self, target_url):
        self.utility.write_log(20, '[In] Predict page type [{}].'.format(self.file_name))
        try:
            # Identify product name and version.
            with codecs.open(self.signature_file, 'r', 'utf-8') as fin:
                matching_patterns = fin.readlines()
                for pattern in matching_patterns:
                    items = pattern.replace('\r', '').replace('\n', '').split('@')
                    page_type = items[0]
                    signature = items[1]
                    obj_match = re.search(signature, target_url, flags=re.IGNORECASE)

                    # Judge page type.
                    if obj_match is not None:
                        msg = 'Identify page type : page type={}/100%, url={}'.format(page_type, target_url)
                        self.utility.print_message(OK, msg)
                        self.utility.write_log(20, msg)
                        self.utility.write_log(20, '[Out] Predict page type [{}].'.format(self.file_name))
                        return page_type, '100.0', obj_match.group(1)

        except Exception as e:
            msg = 'Prediction page type is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)
        self.utility.write_log(20, '[Out] Predict page type [{}].'.format(self.file_name))
        return 'Login', '0.0', '-'

    # Predict page type using HTTP status code.
    def predict_basic_auth(self, response):
        self.utility.write_log(20, '[In] Predict page type [{}].'.format(self.file_name))

        # Identify product name and version.
        obj_match = re.search(r'[\r\n](WWW-Authenticate:\sBasic).*[\r\n]', response, flags=re.IGNORECASE)

        # Judge page type.
        if obj_match is not None:
            reason = obj_match.group(1)
            msg = 'Identify page type : page type={}/100%, reason={}'.format('Login', reason)
            self.utility.print_message(OK, msg)
            self.utility.write_log(20, msg)
            self.utility.write_log(20, '[Out] Predict page type [{}].'.format(self.file_name))
            return 'Login', '100.0', reason

        return 'Login', '0.0', '-'

    # Execute learning / Get learned data.
    def train(self, in_file, out_file):
        self.utility.write_log(20, '[In] Train model [{}].'.format(self.file_name))
        nb = None
        try:
            # If existing learned data (pkl), load learned data.
            if os.path.exists(out_file):
                msg = 'Load trained file : {}'.format(out_file)
                self.utility.print_message(OK, msg)
                self.utility.write_log(20, msg)
                with open(out_file, 'rb') as fin:
                    nb = pickle.load(fin)
            # If no learned data, execute learning.
            else:
                msg = 'Train model : {}'.format(in_file)
                self.utility.print_message(OK, msg)
                self.utility.write_log(20, msg)
                nb = NaiveBayes()
                fin = codecs.open(in_file, 'r', 'utf-8')
                lines = fin.readlines()
                fin.close()
                items = []

                for line in lines:
                    words = line[:-2]
                    train_words = words.split('@')
                    items.append(train_words[1])
                    nb.train(train_words[1], train_words[0])

                # Save learned data to pkl file.
                with open(out_file, 'wb') as f:
                    pickle.dump(nb, f)
        except Exception as e:
            msg = 'Training model is failure : {}'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)
        self.utility.write_log(20, '[Out] Train model [{}].'.format(self.file_name))
        return nb
