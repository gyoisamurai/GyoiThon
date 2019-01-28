#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import configparser
import collections
import pandas as pd
from datetime import datetime


class Creator:
    def __init__(self):
        # Read config.ini.
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        self.target_dir = os.path.join(self.root_path, config['Creator']['target_dir'])
        self.prohibit_ext_list = config['Creator']['prohibit_ext'].split('@')
        self.save_file = config['Creator']['result_file'].replace('*', datetime.now().strftime('%Y%m%d%H%M%S'))
        self.save_path = os.path.join(self.full_path, self.save_file)
        self.header = str(config['Creator']['header']).split('@')

        # Count directory number.
        self.offset_layer_num = self.count_dir_layer(self.target_dir)

    # Count directory layer.
    def count_dir_layer(self, target_dir):
        # Count directory number.
        split_symbol = '/'
        if os.name == 'nt':
            split_symbol = '\\'

        tmp_dir_list = os.path.splitdrive(target_dir)[1].split(split_symbol)
        tmp_dir_list.remove('')
        return len(tmp_dir_list)

    # Grep.
    def execute_grep(self, target_product, target_dir):
        report = []
        if os.path.exists(target_dir):
            for root, dirs, files in os.walk(target_dir):
                file_count = 0
                ext_list = []
                for file in files:
                    print('Check file : {}/{}'.format(root.replace(self.target_dir, ''), file))
                    _, ext = os.path.splitext(file)
                    if ext[1:] not in self.prohibit_ext_list:
                        # Count file number and target extension.
                        file_count += 1
                        ext_list.append(ext[1:])

                # Save information each directory.
                record = []
                record.insert(0, target_product)
                record.insert(1, root.replace(self.target_dir, ''))
                record.insert(2, self.count_dir_layer(root) - self.offset_layer_num)
                record.insert(3, file_count)
                record.insert(4, list(set(ext_list)))
                record.insert(5, collections.Counter(ext_list))
                report.append(record)

            # Save extracted information.
            pd.DataFrame(report).to_csv(self.save_path, mode='a', header=False, index=False)
        else:
            print('Error: Path or file is not found.\n=> {}'.format(target_dir))
            sys.exit(1)

    # Main control.
    def extract_file_structure(self):
        # Extract path and file name from target directory.
        target_list = os.listdir(self.target_dir)

        # Create report header.
        pd.DataFrame([], columns=self.header).to_csv(self.save_path, mode='w', index=False)

        # Extract file structures.
        try:
            for target in target_list:
                # Extract file path each products.
                self.execute_grep(target, os.path.join(self.target_dir, target))
        except Exception as e:
            print('{}'.format(e.args))


if __name__ == '__main__':
    # Create train data.
    creator = Creator()
    creator.extract_file_structure()
    print('finish!!')
