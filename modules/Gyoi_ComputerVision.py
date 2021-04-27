#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import configparser
import pandas as pd
from urllib3 import util
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from util import Utilty

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


class ComputerVision:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'), encoding='utf-8')

        try:
            # Define Web browser's driver path.
            self.driver_dir = os.path.join(self.full_path, config['ComputerVision']['driver_dir'])
            self.chrome_dir = os.path.join(self.driver_dir, config['ComputerVision']['chrome_driver'])
            self.con_timeout = int(config['ComputerVision']['con_timeout'])
            self.ss_implicitly_wait_time = int(config['ComputerVision']['ss_implicitly_wait_time'])
            self.ss_load_wait_time = int(config['ComputerVision']['ss_load_wait_time'])
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            self.utility.write_log(40, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

    # Check executable screen shot.
    def check_executable_ss(self, scheme, sub_domain, status_code, location):
        url = '{}://{}'.format(scheme, sub_domain)
        if type(status_code) is str and status_code.isdecimal():
            if 300 <= int(status_code) < 400:
                if pd.isna(location) is False:
                    extracted_subdomain = util.parse_url(location).host
                    if sub_domain != extracted_subdomain:
                        url = None
                else:
                    url = None
        elif type(status_code) is int:
            if 300 <= status_code < 400:
                if pd.isna(location) is False:
                    extracted_subdomain = util.parse_url(location).host
                    if sub_domain != extracted_subdomain:
                        url = None
                else:
                    url = None
        else:
            url = None
        return url

    # Get Screen shot for Web pages.
    def get_web_screen_shot(self, report_path):
        self.utility.print_message(NOTE, 'Get Screen shot for Web page.')
        msg = self.utility.make_log_msg(self.utility.log_in,
                                        self.utility.log_dis,
                                        self.file_name,
                                        action='Get screen shot.',
                                        note='Get Screen shot.',
                                        dest=self.utility.target_host)
        self.utility.write_log(20, msg)

        # Get inventory report.
        df = pd.read_csv(report_path, delimiter='\t')
        save_dir = os.path.splitext(report_path)[0] + '-screen_shot'
        if os.path.exists(save_dir) is False:
            os.mkdir(save_dir)

        # Set Chrome's Options.
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--hide-scrollbars')
        options.add_argument('--incognito')
        options.add_argument('--ignore-certificate-errors')

        # Set Web browser.
        driver = webdriver.Chrome(executable_path=self.chrome_dir, options=options)
        driver.implicitly_wait(self.ss_implicitly_wait_time)
        driver.set_window_size(1400, 2000)
        driver.set_page_load_timeout(self.con_timeout)

        # Get screen shots.
        ss_items = []
        for sub_domain, http_ret, http_loc, https_ret, https_loc in zip(df['Sub-Domain'],
                                                                        df['Access Status (http)'],
                                                                        df['Location (http)'],
                                                                        df['Access Status (https)'],
                                                                        df['Location (https)']):
            sub_ss_list = []
            for scheme in ['http', 'https']:
                url = None

                # Check executable getting screen shot.
                if scheme == 'http':
                    url = self.check_executable_ss(scheme, sub_domain, http_ret, http_loc)
                else:
                    url = self.check_executable_ss(scheme, sub_domain, https_ret, https_loc)

                # Save screen shot.
                if url is not None:
                    self.utility.print_message(OK, 'The Subdomain "{}://{}" is activation.'.format(scheme, sub_domain))
                    try:
                        # Access to url.
                        driver.get(url)
                        time.sleep(self.ss_load_wait_time)

                        ss_url = driver.current_url
                        ss_subdomain = util.parse_url(ss_url).host
                        if sub_domain.lower() == ss_subdomain.lower():
                            self.utility.print_message(OK, 'Subdomain is match: "{}" <-> "{}"'.format(sub_domain,
                                                                                                      ss_url))

                            # Save screen shot.
                            file_name = '{}_{}.png'.format(scheme, sub_domain)
                            ss_path = os.path.join(save_dir, file_name)
                            driver.save_screenshot(ss_path)
                            self.utility.print_message(OK, 'Screen shot: {}.'.format(ss_path))
                            sub_ss_list.extend([driver.title, ss_url, ss_path])
                        else:
                            self.utility.print_message(WARNING, 'Subdomain is not match: "{}" <-> "{}"'.format(sub_domain,
                                                                                                               ss_url))
                            sub_ss_list.extend([driver.title, ss_url, 'Out of Range.'])
                    except Exception as e:
                        self.utility.print_exception(e, 'Could not get screen shot.')
                        sub_ss_list.extend(['Error.', 'Error.', 'Error.'])
                else:
                    self.utility.print_message(WARNING, 'The Subdomain "{}://{}" is inactivation.'.format(scheme,
                                                                                                          sub_domain))
                    sub_ss_list.extend(['N/A', 'N/A', 'N/A'])
            ss_items.append(sub_ss_list)

        driver.close()
        return ss_items, df
