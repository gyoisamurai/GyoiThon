#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import configparser
import sqlite3


# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.


# Database control class.
class DbControl:
    def __init__(self, utility):
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.utility = utility

        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        config.read(os.path.join(full_path, 'config.ini'), encoding='utf-8')

        try:
            db_path = os.path.join(full_path, config['GyoiBoard']['gyoiboard_path'])
            self.db_file = os.path.join(db_path, config['GyoiBoard']['gyoiboard_db'])
            self.con_timeout = int(config['GyoiBoard']['con_timeout'])
            self.isolation_level = config['GyoiBoard']['isolation_level']

            # Create or connect to database.
            self.conn = None
            if os.path.exists(self.db_file) is False:
                # Create table.
                self.db_initialize('scan_result')
            else:
                # Create connection.
                self.conn = sqlite3.connect(self.db_file,
                                            timeout=self.con_timeout,
                                            isolation_level=self.isolation_level)
        except Exception as e:
            self.utility.print_message(FAIL, 'Reading config.ini is failure : {}'.format(e))
            sys.exit(1)

        # Query templates for searching gyoithon_subdomain.
        self.search_subdomain_select = 'SELECT * FROM gyoithon_subdomain ' \
                                       'WHERE related_organization_id = ? AND related_domain_id = ? AND name = ?'
        self.search_subdomain_insert = 'INSERT INTO gyoithon_subdomain (' \
                                       'related_organization_id, ' \
                                       'related_domain_id,' \
                                       'name,' \
                                       'ip_address,' \
                                       'cloud_type, ' \
                                       'production, ' \
                                       'url_origin, ' \
                                       'auth_form, ' \
                                       'auth_basic, ' \
                                       'http_accessible,' \
                                       'http_location,' \
                                       'http_page_title, ' \
                                       'http_screenshot_url,' \
                                       'http_screenshot_path,' \
                                       'https_accessible,' \
                                       'https_location,' \
                                       'https_page_title,' \
                                       'https_screenshot_url,' \
                                       'https_screenshot_path,' \
                                       'dns_a_record,' \
                                       'dns_cname_record,' \
                                       'dns_ns_record,' \
                                       'dns_mx_record,' \
                                       'dns_soa_record,' \
                                       'dns_txt_record,' \
                                       'rank,' \
                                       'status, ' \
                                       'invisible,' \
                                       'registration_date) ' \
                                       'VALUES (?,?,?,?,0,0,"","","",?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,0,?)'
        self.search_subdomain_update = 'UPDATE gyoithon_subdomain ' \
                                       'SET ' \
                                       'ip_address = ?,' \
                                       'http_accessible = ?,' \
                                       'http_location = ?' \
                                       'http_page_title = ?, ' \
                                       'http_screenshot_url = ?, ' \
                                       'http_screenshot_path = ?, ' \
                                       'https_accessible = ?, ' \
                                       'https_location = ?, ' \
                                       'https_page_title = ?, ' \
                                       'https_screenshot_url = ?, ' \
                                       'https_screenshot_path = ?, ' \
                                       'dns_a_record = ?,' \
                                       'dns_cname_record = ?, ' \
                                       'dns_ns_record = ?, ' \
                                       'dns_mx_record = ?, ' \
                                       'dns_soa_record = ?, ' \
                                       'dns_txt_record = ?, ' \
                                       'WHERE related_organization_id = ? AND related_domain_id = ? AND name = ?'

    # Execute INSERT query.
    def insert(self, conn, sql_query, params):
        self.utility.write_log(20, '[In] Execute INSERT query [{}].'.format(self.file_name))
        conn.execute('begin transaction')
        conn.execute(sql_query, params)
        conn.commit()
        self.utility.write_log(20, '[Out] Execute INSERT query [{}].'.format(self.file_name))

    # Execute UPDATE query.
    def update(self, conn, sql_query, params):
        self.utility.write_log(20, '[In] Execute UPDATE query [{}].'.format(self.file_name))
        conn.execute('begin transaction')
        conn.execute(sql_query, params)
        conn.commit()
        self.utility.write_log(20, '[Out] Execute UPDATE query [{}].'.format(self.file_name))

    # Execute DELETE query.
    def delete(self, conn, sql_query, params=()):
        self.utility.write_log(20, '[In] Execute DELETE query [{}].'.format(self.file_name))
        conn.execute('begin transaction')
        conn.execute(sql_query, params)
        conn.commit()
        self.utility.write_log(20, '[Out] Execute DELETE query [{}].'.format(self.file_name))

    # Execute SELECT query.
    def select(self, conn, sql_query, params=()):
        self.utility.write_log(20, '[In] Execute SELECT query [{}].'.format(self.file_name))
        cursor = conn.cursor()
        cursor.execute(sql_query, params)
        self.utility.write_log(20, '[Out] Execute SELECT query [{}].'.format(self.file_name))
        return cursor
