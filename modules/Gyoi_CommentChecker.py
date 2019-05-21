#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs
import re
import configparser
from bs4 import BeautifulSoup
from bs4 import Comment

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


class CommentChecker:
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
            self.signature_file = config['CommentChecker']['signature_file']
            self.signature_path = os.path.join(self.signature_dir, self.signature_file)
            self.action_name = 'Comment Check'
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Get html comments.
    def get_html_comments(self, soup):
        self.utility.write_log(20, '[In] Get html comments [{}].'.format(self.file_name))

        temp_comment_list = list(set(soup.find_all(string=lambda text: isinstance(text, Comment))))

        # Delete IE condition (ex. "[if IE 9").
        comment_list = []
        for comment in temp_comment_list:
            if len(comment) < 3 or comment[:3].lower() != '[if':
                comment_list.append(comment)

        self.utility.write_log(20, '[Out] Get html comments [{}].'.format(self.file_name))
        return comment_list

    # Get JavaScript comments.
    def get_js_comments(self, soup):
        self.utility.write_log(20, '[In] Get Javascript comments [{}].'.format(self.file_name))

        js_comment_list = []
        script_tags = soup.find_all('script')
        for script_tag in script_tags:
            target_text = script_tag.get_text()
            js_comment_list.extend(re.findall(r'(/\*[\s\S]*?\*/)', target_text))
            js_comment_list.extend(re.findall(r'(^//.*[\r\n]|\s//.*[\r\n])', target_text))

        self.utility.write_log(20, '[Out] Get Javascript comments [{}].'.format(self.file_name))
        return list(set(js_comment_list))

    # Check unnecessary comments.
    def get_bad_comment(self, response):
        self.utility.print_message(NOTE, 'Check unnecessary comments.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check unnecessary comments.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Check comment.
        comment_list = []
        bad_comment_list = []
        soup = BeautifulSoup(response, 'html.parser')

        # Get comments.
        comment_list.extend(self.get_html_comments(soup))
        comment_list.extend(self.get_js_comments(soup))
        try:
            # Open signature file.
            with codecs.open(self.signature_path, 'r', 'utf-8') as fin:
                matching_patterns = fin.readlines()
                for comment in comment_list:
                    for signature in matching_patterns:
                        try:
                            # Find bad comments.
                            pattern = signature.replace('\r', '').replace('\n', '')
                            obj_match = re.search(pattern, comment, flags=re.IGNORECASE)

                            if obj_match is not None:
                                trigger = obj_match.group(1)
                                bad_comment_list.append(trigger)
                                msg = 'Detect unnecessary comment: {}'.format(trigger)
                                self.utility.print_message(OK, msg)
                                msg = self.utility.make_log_msg(self.utility.log_mid,
                                                                self.utility.log_dis,
                                                                self.file_name,
                                                                action=self.action_name,
                                                                note=msg,
                                                                dest=self.utility.target_host)
                                self.utility.write_log(20, msg)
                                break
                        except Exception as e:
                            self.utility.print_exception(e, 'Invalid signature: {}, {}'.format(signature, e))
                            self.utility.write_log(30, '{}'.format(e))
        except Exception as e:
            self.utility.print_exception(e, 'Getting comment is failure :{}.'.format(e))
            self.utility.write_log(30, 'Getting comment is failure :{}.'.format(e))

        msg = self.utility.make_log_msg(self.utility.log_out,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action=self.action_name,
                                        note='Check unnecessary comments.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)
        if len(bad_comment_list) == 0:
            self.utility.print_message(OK, 'Unnecessary comment not found.')
        return list(set(bad_comment_list)), comment_list
