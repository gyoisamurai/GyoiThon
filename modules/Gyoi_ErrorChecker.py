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


class ErrorChecker:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        try:
            self.signature_dir = os.path.join(self.root_path, config['Common']['signature_path'])
            self.signature_file = config['ErrorChecker']['signature_file']
            self.signature_path = os.path.join(self.signature_dir, self.signature_file)
            self.action_name = 'Error Checker'
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Check unnecessary error message.
    def get_error_message(self, response):
        self.utility.print_message(NOTE, 'Check unnecessary error message.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check unnecessary error message',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Check comment.
        error_list = []
        try:
            # Open signature file.
            with codecs.open(self.signature_path, 'r', 'utf-8') as fin:
                matching_patterns = fin.readlines()
                for signature in matching_patterns:
                    try:
                        # Find bad message.
                        pattern = signature.replace('\r', '').replace('\n', '')
                        obj_match = re.search(pattern, response, flags=re.IGNORECASE)

                        if obj_match is not None:
                            trigger = obj_match.group(1)
                            error_list.append(trigger)
                            msg = 'Detect unnecessary message: {}'.format(trigger)
                            self.utility.print_message(OK, msg)
                            msg = self.utility.make_log_msg(self.utility.log_mid,
                                                            self.utility.log_dis,
                                                            self.file_name,
                                                            action=self.action_name,
                                                            note=msg,
                                                            dest=self.utility.target_host)
                            self.utility.write_log(20, msg)
                    except Exception as e:
                        self.utility.print_exception(e, 'Invalid signature: {}, {}'.format(signature, e))
                        self.utility.write_log(30, '{}'.format(e))
        except Exception as e:
            msg = 'Getting error message is failure : {}.'.format(e)
            self.utility.print_exception(e, msg)
            self.utility.write_log(30, msg)

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check unnecessary error message',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        if len(error_list) == 0:
            self.utility.print_message(OK, 'Unnecessary error message not found.')
        return list(set(error_list))
