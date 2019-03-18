#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import csv
import zipfile
import tarfile
import configparser
import collections
import statistics
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from datetime import datetime

# Type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.

# Type of train data.
OS = 0
WEB = 1
FRAMEWORK = 2
CMS = 3


class Creator:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        # Define master signature file path.
        master_sig_dir = os.path.join(self.root_path, config['Common']['signature_path'])
        self.master_prod_sig = os.path.join(master_sig_dir, config['VersionChecker']['signature_file'])
        self.master_cont_sig = os.path.join(master_sig_dir, config['ContentExplorer']['signature_file'])
        self.pd_prod_sig = pd.read_csv(self.master_prod_sig,
                                       delimiter='@', encoding='utf-8', header=None, quoting=csv.QUOTE_NONE)
        self.pd_cont_sig = pd.read_csv(self.master_cont_sig,
                                       delimiter='@', encoding='utf-8', header=None, quoting=csv.QUOTE_NONE)
        self.delete_prod_row_index = []
        self.delete_cont_row_index = []

        # Define master train data path.
        self.train_categories = config['VersionCheckerML']['category'].split('@')
        train_dir = os.path.join(self.full_path, config['VersionCheckerML']['train_path'])
        self.train_os_in = os.path.join(train_dir, config['VersionCheckerML']['train_os_in'])
        self.train_web_in = os.path.join(train_dir, config['VersionCheckerML']['train_web_in'])
        self.train_framework_in = os.path.join(train_dir, config['VersionCheckerML']['train_framework_in'])
        self.train_cms_in = os.path.join(train_dir, config['VersionCheckerML']['train_cms_in'])
        for category in self.train_categories:
            if category == 'OS':
                self.pd_train_os = pd.read_csv(self.train_os_in,
                                               delimiter='@', encoding='utf-8', header=None, quoting=csv.QUOTE_NONE)
            elif category == 'WEB':
                self.pd_train_web = pd.read_csv(self.train_web_in,
                                                delimiter='@', encoding='utf-8', header=None, quoting=csv.QUOTE_NONE)
            elif category == 'FRAMEWORK':
                self.pd_train_fw = pd.read_csv(self.train_framework_in,
                                               delimiter='@', encoding='utf-8', header=None, quoting=csv.QUOTE_NONE)
            elif category == 'CMS':
                self.pd_train_cms = pd.read_csv(self.train_cms_in,
                                                delimiter='@', encoding='utf-8', header=None, quoting=csv.QUOTE_NONE)
            else:
                self.utility.print_message(FAIL, 'Choose category is not found.')
                exit(1)
        self.delete_train_os_row_index = []
        self.delete_train_web_row_index = []
        self.delete_train_fw_row_index = []
        self.delete_train_cms_row_index = []

        self.compress_dir = os.path.join(self.root_path, config['Creator']['compress_dir'])
        self.signature_dir = os.path.join(self.root_path, config['Creator']['signature_dir'])
        self.prohibit_ext_list = config['Creator']['prohibit_ext'].split('@')
        self.save_file = config['Creator']['result_file'].replace('*', datetime.now().strftime('%Y%m%d%H%M%S'))
        self.save_path = os.path.join(self.signature_dir, self.save_file)
        self.header = str(config['Creator']['header']).split('@')
        self.score_table_path = os.path.join(self.full_path, config['Exploit']['data_path'])
        self.score_table = os.path.join(self.score_table_path, config['Creator']['score_table'])
        self.threshold = float(config['Creator']['threshold'])
        self.unknown_score = float(config['Creator']['unknown_score'])
        self.turn_inside_num = int(config['Creator']['turn_inside_num'])
        if self.turn_inside_num > 2:
            self.turn_inside_num = 2
        self.try_othello_num = int(config['Creator']['try_othello_num'])

        # Check necessary directories.
        self.is_dir_existance(self.compress_dir)
        self.is_dir_existance(self.signature_dir)

        # Load score table.
        self.pd_score_table = pd.read_csv(self.score_table)

    # Check necessary directory.
    def is_dir_existance(self, target_dir):
        if os.path.exists(target_dir) is False:
            os.mkdir(target_dir)
            self.utility.print_message(WARNING, 'Directory is not found: {}.'.format(target_dir))
            self.utility.print_message(WARNING, 'Maked directory: {}.'.format(target_dir))

    # Count directory layer.
    def count_dir_layer(self, target_dir):
        # Count directory number.
        split_symbol = '/'
        if os.name == 'nt':
            split_symbol = '\\'

        tmp_dir_list = os.path.splitdrive(target_dir)[1].split(split_symbol)
        tmp_dir_list.remove('')
        return len(tmp_dir_list), tmp_dir_list

    # Grep.
    def execute_grep(self, target_product, target_dir):
        base_index = 0
        report = []
        if os.path.exists(target_dir):
            for root, _, files in os.walk(target_dir):
                file_count = 0
                ext_list = []
                for file in files:
                    msg = 'Check file : {}/{}'.format(root.replace(target_dir, '').replace('\\', '/'), file)
                    self.utility.print_message(OK, msg)
                    _, ext = os.path.splitext(file)
                    if ext[1:] not in self.prohibit_ext_list:
                        # Count file number and target extension.
                        file_count += 1
                        ext_list.append(ext[1:])

                # Save information each directory.
                record = []
                record.insert(0, base_index)
                record.insert(1, target_product)
                record.insert(2, root.replace(target_dir, ''))
                record.insert(3, list(set(ext_list)))
                record.insert(4, collections.Counter(ext_list))
                record.insert(5, list(set(files)))
                report.append(record)
                base_index += 1

            # Save extracted information.
            pd.DataFrame(report).to_csv(self.save_path, mode='a', header=False, index=False)
        else:
            self.utility.print_message(FAIL, 'Path or file is not found.\n=> {}'.format(target_dir))
            sys.exit(1)
        return report

    # Show graph.
    def show_graph(self, target, graph):
        self.utility.print_message(NOTE, 'Creating network image...')
        plt.figure(figsize=(10, 10))
        nx.draw_networkx(graph)
        plt.axis('off')
        file_name = os.path.join(self.full_path, target + '.png')
        plt.savefig(file_name)
        plt.show()

    # Calculate score of node.
    def calc_score(self, ext_type):
        score_list = []
        for ext in ext_type:
            # Get defined score from score table.
            pd_score = self.pd_score_table[self.pd_score_table['extension'] == ext.lower()]

            # Calculate score.
            if len(pd_score) != 0:
                if pd_score['probability'].values[0] == 1.0:
                    return 1.0
                elif pd_score['probability'].values[0] == 0.0:
                    return 0.0
                else:
                    score_list.append(pd_score['probability'].values[0])
            else:
                score_list.append(self.unknown_score)
        return statistics.median(score_list)

    # Return score of extension.
    def return_score(self, files):
        total_file_score = 0.0
        for file in files:
            _, ext = os.path.splitext(file)
            pd_score = self.pd_score_table[self.pd_score_table['extension'] == ext[1:].lower()]
            if len(pd_score) > 0:
                total_file_score += pd_score['probability'].values[0]
        return total_file_score

    # Set node label.
    def set_node_label(self, score):
        label = 0.0
        if score == 0.0:
            label = 0.00
        elif 0.1 <= score <= 0.3:
            label = 0.25
        elif 0.4 <= score <= 0.6:
            label = 0.50
        elif 0.7 < score <= 0.9:
            label = 0.75
        elif score == 1.0:
            label = 1.00
        return label

    # Create Network using networkx.
    def create_network(self, records):
        # Create direction graph.
        graph = nx.DiGraph()
        dir_pool = {}
        node_index = 0
        for index, record in enumerate(records):
            self.utility.print_message(NOTE, '{}/{} Analyzing "{}"'.format(index + 1, len(records), record[2]))
            _, dirs = self.count_dir_layer(record[2])
            parent_dir = ''
            label = '\\'
            for layer_index, dir_name in enumerate(dirs):
                label += str(dir_name) + '\\'

                # Set parent node.
                if label in dir_pool.keys():
                    parent_dir = label
                else:
                    # Calculate score and classification.
                    score = 0.0
                    if len(record[3]) != 0:
                        score = self.calc_score(record[3])
                    rank = self.set_node_label(score)

                    # Add new node within attributes.
                    dir_pool[label] = node_index
                    graph.add_node(node_index,
                                   path=record[2],
                                   ext_type=record[3],
                                   ext_count=record[4],
                                   files=record[5],
                                   score=score,
                                   rank=rank)
                    node_index += 1

                    # Create edge that connecting two nodes.
                    if parent_dir != '' and label != parent_dir:
                        graph.add_edge(dir_pool[parent_dir], dir_pool[label])
                        msg = 'Create edge node.{} <-> node.{}'.format(dir_pool[parent_dir], dir_pool[label])
                        self.utility.print_message(OK, msg)
        return graph

    # Extract tar file.
    def extract_tar(self, file, path):
        with tarfile.open(file) as tf:
            tf.extractall(path)

    # Extract zip file.
    def extract_zip(self, file, path):
        with zipfile.ZipFile(file) as zf:
            zf.extractall(os.path.join(path))

    # Decompress compressed package file.
    def decompress_file(self, package_path):
        # Extract path and file name from target directory.
        self.utility.print_message(NOTE, 'Starting decompress: {}.'.format(package_path))

        # Create extraction directory name.
        extract_dir_name = ''
        if '.tar' in os.path.splitext(package_path)[0]:
            extract_dir_name = os.path.splitext(package_path)[0]
        else:
            extract_dir_name = os.path.splitext(package_path)[0].replace('.tar', '')

        try:
            # Execute extraction.
            if '.tar' in package_path:
                self.utility.print_message(OK, 'Decompress... : {}'.format(package_path))
                self.extract_tar(package_path, extract_dir_name)
            elif '.zip' in package_path:
                self.utility.print_message(OK, 'Decompress... : {}'.format(package_path))
                self.extract_zip(package_path, extract_dir_name)
        except Exception as e:
            self.utility.print_exception(e, '{}'.format(e.args))
        return extract_dir_name

    # Explore open path.
    def explore_open_path(self, graph, all_paths):
        open_paths = []
        for idx, path in enumerate(all_paths):
            tmp_open_paths = []
            close_path_index = len(path) - 1
            self.utility.print_message(NOTE, '{}/{} Explore path: {}'.format(idx + 1, len(all_paths), path))
            for idx2, node_index in enumerate(path[::-1]):
                msg = 'Checking turn inside node.{}:{}'.format(node_index, graph.nodes[node_index]['path'])
                self.utility.print_message(OK, msg)

                # Add open path.
                rank = graph.nodes[node_index]['rank']
                if graph.nodes[node_index]['rank'] >= self.threshold:
                    self.utility.print_message(OK, 'Add node {} to open path list.'.format(node_index))
                    tmp_open_paths.append([node_index, graph.nodes[node_index]['path'], rank])

                    # Set close path index.
                    close_path_index = len(path) - idx2 - 2
                # Execute "Othello".
                elif 0 < (len(path) - idx2 - 1) < len(path) - 1:
                    # Extract ranks of parent and child node.
                    parent_node_rank = graph.nodes[path[len(path) - idx2 - 2]]['rank']
                    child_node_rank = graph.nodes[path[len(path) - idx2]]['rank']

                    # Checking turn inside the node rank.
                    if parent_node_rank >= self.threshold and child_node_rank >= self.threshold:
                        msg = 'Turned inside rank={} -> 1.0.'.format(graph.nodes[node_index]['rank'])
                        self.utility.print_message(WARNING, msg)
                        self.utility.print_message(WARNING, 'Add node {} to open path list.'.format(node_index))
                        tmp_open_paths.append([node_index, graph.nodes[node_index]['path'], 1.0])
                        graph.nodes[node_index]['rank'] = 1.0

                        # Set close path index.
                        close_path_index = len(path) - idx2 - 2
                    else:
                        if close_path_index < len(path) - idx2 - 1:
                            # Set close path index.
                            close_path_index = len(path) - idx2 - 1
                # Do not execute "Othello".
                else:
                    if close_path_index < len(path) - idx2 - 1:
                        # Set close path index.
                        close_path_index = len(path) - idx2 - 1

            # Cut unnecessary path (root path -> open path).
            if close_path_index != -1:
                for tmp_path in tmp_open_paths:
                    delete_seq = len(graph.nodes[path[close_path_index]]['path'])
                    open_paths.append([tmp_path[0], tmp_path[1][delete_seq:], tmp_path[2]])
            else:
                open_paths.extend(tmp_open_paths)

        return list(map(list, set(map(tuple, open_paths))))

    # Check existing path signature.
    def is_path_sig_existing(self, target):
        # If existing regex and new regex are duplicate, both signatures are deleted.
        ret = True
        df_extract_sig = self.pd_prod_sig[self.pd_prod_sig[4] == target]
        if len(df_extract_sig) != 0:
            # Delete existing signature and does not add new signature.
            for del_index in df_extract_sig.index:
                self.delete_prod_row_index.append(del_index)
        else:
            ret = False
        return ret

    # Check existing file signature.
    def is_file_sig_existing(self, target):
        # If existing regex and new regex are duplicate, both signatures are deleted.
        ret = True
        df_extract_sig = self.pd_cont_sig[self.pd_cont_sig[4] == target]
        if len(df_extract_sig) != 0:
            # Delete existing signature and does not new signature.
            for del_index in df_extract_sig.index:
                self.delete_cont_row_index.append(del_index)
        else:
            ret = False
        return ret

    # Check existing train data.
    def is_train_data_existing(self, category, target):
        # Check existing train data.
        ret = False
        if category == 'OS':
            df_extract_train = self.pd_train_os[self.pd_train_os[4] == target]
            for del_index in df_extract_train.index:
                self.delete_train_os_row_index.append(del_index)
                ret = True
        elif category == 'WEB':
            df_extract_train = self.pd_train_web[(self.pd_train_web[4] == target)]
            for del_index in df_extract_train.index:
                self.delete_train_web_row_index.append(del_index)
                ret = True
        elif category == 'FRAMEWORK':
            df_extract_train = self.pd_train_fw[(self.pd_train_fw[4] == target)]
            for del_index in df_extract_train.index:
                self.delete_train_fw_row_index.append(del_index)
                ret = True
        elif category == 'CMS':
            df_extract_train = self.pd_train_cms[(self.pd_train_cms[4] == target)]
            for del_index in df_extract_train.index:
                self.delete_train_cms_row_index.append(del_index)
                ret = True
        return ret

    def add_train_data(self, category, vendor, prod_name, prod_ver, files, target_path):
        category_list = []
        vendor_list = []
        prod_name_list = []
        version_list = []
        path_list = []
        ret = self.is_train_data_existing(category, '(' + target_path + ')')

        # Add train data info to temporally buffer.
        if ret is False:
            category_list.append(category)
            vendor_list.append(vendor)
            prod_name_list.append(prod_name)
            version_list.append(prod_ver)
            path_list.append('(' + target_path + ')')

        # Add file path signature info to temporally buffer.
        for file in files:
            target_file = '(' + target_path + file + ')'
            ret = self.is_train_data_existing(category, target_file)
            if ret is False:
                category_list.append(category)
                vendor_list.append(vendor)
                prod_name_list.append(prod_name)
                version_list.append(prod_ver)
                path_list.append(target_file)
        return category_list, vendor_list, prod_name_list, version_list, path_list

    # Main control.
    def extract_file_structure(self, category, vendor, package):
        # Check package path.
        package_path = os.path.join(self.compress_dir, package)
        if os.path.exists(package_path) is False:
            self.utility.print_message(FAIL, 'Package is not found: {}.'.format(package_path))
            return

        # Decompress compressed package file.
        extract_path = self.decompress_file(package_path)

        # Extract product name and version.
        # ex) Package name must be "wordpress_4.9.8_.tar.gz".
        package_info = package.split('@')
        prod_name = ''
        prod_ver = ''
        if len(package_info) < 2:
            prod_name = package_info[0]
            prod_ver = 'unknown'
        else:
            prod_name = package_info[0]
            prod_ver = package_info[1]

        # Create report header.
        pd.DataFrame([], columns=self.header).to_csv(self.save_path, mode='w', index=False)

        # Extract file structures.
        try:
            # Extract file path each products.
            target_name = prod_name + ' ' + prod_ver
            self.utility.print_message(NOTE, 'Extract package {}'.format(extract_path))
            record = self.execute_grep(target_name, extract_path)
            graph = self.create_network(record)

            # Extract all paths to end node from root node.
            all_paths = []
            node_num = len(graph._adj)
            for end_node_idx in range(node_num):
                msg = '{}/{} Analyzing node={}'.format(end_node_idx + 1, node_num, end_node_idx)
                self.utility.print_message(OK, msg)
                if len(graph._adj[end_node_idx]) == 0:
                    for path in nx.all_simple_paths(graph, source=0, target=end_node_idx):
                        msg = 'Extract path that source={} <-> target={}, path={}'.format(0, end_node_idx, path)
                        self.utility.print_message(OK, msg)
                        all_paths.append(path)

            # Execute "Othello".
            open_paths = []
            for try_num in range(self.try_othello_num):
                self.utility.print_message(OK, '{}/{} Execute "Othello".'.format(try_num + 1, self.try_othello_num))
                open_paths.extend(self.explore_open_path(graph, all_paths))

            # Create signature.
            open_paths = list(map(list, set(map(tuple, open_paths))))

            # Initialize temporally buffer.
            sig_file = []
            for _ in range(len(self.pd_prod_sig.columns)):
                sig_file.append([])
            sig_path = []
            for _ in range(len(self.pd_cont_sig.columns)):
                sig_path.append([])
            train = []
            for _ in range(len(self.train_categories)):
                temp = []
                for _ in range(len(self.pd_train_os.columns)):
                    temp.append([])
                train.append(temp)

            for idx, item in enumerate(open_paths):
                # Create signature.
                files = graph.nodes[item[0]]['files']
                if item[2] == 1.0 and len(files) > 0:
                    # Create target path.
                    target_path = item[1].replace('\\', '/')
                    if target_path.endswith('/') is False:
                        target_path += '/'

                    # Add signature to master signature file.
                    if self.return_score(files) / len(files) == 1.0:
                        # Add path signature info to temporally buffer.
                        if self.is_path_sig_existing(target_path) is False:
                            sig_path[0].append(category)
                            sig_path[1].append(vendor)
                            sig_path[2].append(prod_name)
                            sig_path[3].append(prod_ver)
                            sig_path[4].append(target_path)
                            sig_path[5].append('*')
                            sig_path[6].append('*')
                            sig_path[7].append('0')
                            self.utility.print_message(OK, '{}/{} Add path signature: {}.'.format(idx + 1,
                                                                                                  len(open_paths),
                                                                                                  target_path))
                        # Add file path signature info to temporally buffer.
                        for file in files:
                            target_file = '(' + target_path + file + ')'
                            if self.is_file_sig_existing(target_file) is False:
                                sig_file[0].append(category)
                                sig_file[1].append(vendor)
                                sig_file[2].append(prod_name)
                                sig_file[3].append(prod_ver)
                                sig_file[4].append(target_file)
                                self.utility.print_message(OK, '{}/{} Add file signature: {}.'.format(idx + 1,
                                                                                                      len(open_paths),
                                                                                                      target_file))
                    else:
                        # Add train data info to temporally buffer.
                        categories, vendors, prods, versions, targets = self.add_train_data(category,
                                                                                            vendor,
                                                                                            prod_name,
                                                                                            prod_ver,
                                                                                            files,
                                                                                            target_path)
                        if len(categories) == 0:
                            continue
                        if category == 'OS':
                            train[OS][0].extend(categories)
                            train[OS][1].extend(vendors)
                            train[OS][2].extend(prods)
                            train[OS][3].extend(versions)
                            train[OS][4].extend(targets)
                        elif category == 'WEB':
                            train[WEB][0].extend(categories)
                            train[WEB][1].extend(vendors)
                            train[WEB][2].extend(prods)
                            train[WEB][3].extend(versions)
                            train[WEB][4].extend(targets)
                        elif category == 'FRAMEWORK':
                            train[FRAMEWORK][0].extend(categories)
                            train[FRAMEWORK][1].extend(vendors)
                            train[FRAMEWORK][2].extend(prods)
                            train[FRAMEWORK][3].extend(versions)
                            train[FRAMEWORK][4].extend(targets)
                        elif category == 'CMS':
                            train[CMS][0].extend(categories)
                            train[CMS][1].extend(vendors)
                            train[CMS][2].extend(prods)
                            train[CMS][3].extend(versions)
                            train[CMS][4].extend(targets)
                        self.utility.print_message(OK, '{}/{} Add train data: {}.'.format(idx + 1,
                                                                                          len(open_paths),
                                                                                          target_path))
                # Create train data.
                elif item[2] >= self.threshold:
                    target_path = item[1].replace('\\', '/')
                    if target_path.endswith('/') is False:
                        target_path += '/'
                    categories, vendors, prods, versions, targets = self.add_train_data(category,
                                                                                        vendor,
                                                                                        prod_name,
                                                                                        prod_ver,
                                                                                        files,
                                                                                        target_path)
                    if len(categories) == 0:
                        continue
                    if category == 'OS':
                        train[OS][0].extend(categories)
                        train[OS][1].extend(vendors)
                        train[OS][2].extend(prods)
                        train[OS][3].extend(versions)
                        train[OS][4].extend(targets)
                    elif category == 'WEB':
                        train[WEB][0].extend(categories)
                        train[WEB][1].extend(vendors)
                        train[WEB][2].extend(prods)
                        train[WEB][3].extend(versions)
                        train[WEB][4].extend(targets)
                    elif category == 'FRAMEWORK':
                        train[FRAMEWORK][0].extend(categories)
                        train[FRAMEWORK][1].extend(vendors)
                        train[FRAMEWORK][2].extend(prods)
                        train[FRAMEWORK][3].extend(versions)
                        train[FRAMEWORK][4].extend(targets)
                    elif category == 'CMS':
                        train[CMS][0].extend(categories)
                        train[CMS][1].extend(vendors)
                        train[CMS][2].extend(prods)
                        train[CMS][3].extend(versions)
                        train[CMS][4].extend(targets)
                    self.utility.print_message(OK, '{}/{} Add train data: {}.'.format(idx + 1,
                                                                                      len(open_paths),
                                                                                      target_path))

            # Write path signature to master signature file.
            if len(sig_path[0]) != 0:
                self.pd_cont_sig = self.pd_cont_sig.drop(self.delete_cont_row_index)
                series_category = pd.Series(sig_path[0])
                series_vendor = pd.Series(sig_path[1])
                series_prod = pd.Series(sig_path[2])
                series_version = pd.Series(sig_path[3])
                series_signature = pd.Series(sig_path[4])
                series_dummy1 = pd.Series(sig_path[5])
                series_dummy2 = pd.Series(sig_path[6])
                series_dummy3 = pd.Series(sig_path[7])
                temp_df = pd.DataFrame({0: series_category,
                                        1: series_vendor,
                                        2: series_prod,
                                        3: series_version,
                                        4: series_signature,
                                        5: series_dummy1,
                                        6: series_dummy2,
                                        7: series_dummy3}, columns=None)
                self.pd_cont_sig = pd.concat([self.pd_cont_sig, temp_df])
                self.pd_cont_sig.to_csv(self.master_cont_sig,
                                        sep='@', encoding='utf-8', header=False, index=False, quoting=csv.QUOTE_NONE)
                self.utility.print_message(OK, 'Add Path signature: {} items.'.format(len(sig_path)))

            # Write file signature to master signature file.
            if len(sig_file[0]) != 0:
                self.pd_prod_sig = self.pd_prod_sig.drop(self.delete_prod_row_index)
                series_category = pd.Series(sig_file[0])
                series_vendor = pd.Series(sig_file[1])
                series_prod = pd.Series(sig_file[2])
                series_version = pd.Series(sig_file[3])
                series_signature = pd.Series(sig_file[4])
                temp_df = pd.DataFrame({0: series_category,
                                        1: series_vendor,
                                        2: series_prod,
                                        3: series_version,
                                        4: series_signature}, columns=None)
                self.pd_prod_sig = pd.concat([self.pd_prod_sig, temp_df])
                self.pd_prod_sig.to_csv(self.master_prod_sig,
                                        sep='@', encoding='utf-8', header=False, index=False, quoting=csv.QUOTE_NONE)
                self.utility.print_message(OK, 'Add File signature: {} items.'.format(len(sig_file)))

            # Write OS train data to master train data.
            if train[OS][0] != '':
                self.pd_train_os = self.pd_train_os.drop(self.delete_train_os_row_index)
                series_category = pd.Series(train[OS][0])
                series_vendor = pd.Series(train[OS][1])
                series_prod = pd.Series(train[OS][2])
                series_version = pd.Series(train[OS][3])
                series_signature = pd.Series(train[OS][4])
                temp_df = pd.DataFrame({0: series_category,
                                        1: series_vendor,
                                        2: series_prod,
                                        3: series_version,
                                        4: series_signature}, columns=None)
                self.pd_train_os = pd.concat([self.pd_train_os, temp_df])
                self.pd_train_os.to_csv(self.train_os_in,
                                        sep='@', encoding='utf-8', header=False, index=False, quoting=csv.QUOTE_NONE)
                self.utility.print_message(OK, 'Add OS train data: {} items.'.format(len(train[OS])))

            # Write Web train data to master train data.
            if train[WEB][0] != '':
                self.pd_train_web = self.pd_train_web.drop(self.delete_train_web_row_index)
                series_category = pd.Series(train[WEB][0])
                series_vendor = pd.Series(train[WEB][1])
                series_prod = pd.Series(train[WEB][2])
                series_version = pd.Series(train[WEB][3])
                series_signature = pd.Series(train[WEB][4])
                temp_df = pd.DataFrame({0: series_category,
                                        1: series_vendor,
                                        2: series_prod,
                                        3: series_version,
                                        4: series_signature}, columns=None)
                self.pd_train_web = pd.concat([self.pd_train_web, temp_df])
                self.pd_train_web.to_csv(self.train_web_in,
                                         sep='@', encoding='utf-8', header=False, index=False, quoting=csv.QUOTE_NONE)
                self.utility.print_message(OK, 'Add OS train data: {} items.'.format(len(train[WEB])))

            # Write Framework train data to master train data.
            if train[FRAMEWORK] != '':
                self.pd_train_fw = self.pd_train_fw.drop(self.delete_train_fw_row_index)
                series_category = pd.Series(train[FRAMEWORK][0])
                series_vendor = pd.Series(train[FRAMEWORK][1])
                series_prod = pd.Series(train[FRAMEWORK][2])
                series_version = pd.Series(train[FRAMEWORK][3])
                series_signature = pd.Series(train[FRAMEWORK][4])
                temp_df = pd.DataFrame({0: series_category,
                                        1: series_vendor,
                                        2: series_prod,
                                        3: series_version,
                                        4: series_signature}, columns=None)
                self.pd_train_fw = pd.concat([self.pd_train_fw, temp_df])
                self.pd_train_fw.to_csv(self.train_framework_in,
                                        sep='@', encoding='utf-8', header=False, index=False, quoting=csv.QUOTE_NONE)
                self.utility.print_message(OK, 'Add OS train data: {} items.'.format(len(train[FRAMEWORK])))

            # Write CMS train data to master train data.
            if train[CMS][0] != '':
                self.pd_train_cms = self.pd_train_cms.drop(self.delete_train_cms_row_index)
                series_category = pd.Series(train[CMS][0])
                series_vendor = pd.Series(train[CMS][1])
                series_prod = pd.Series(train[CMS][2])
                series_version = pd.Series(train[CMS][3])
                series_signature = pd.Series(train[CMS][4])
                temp_df = pd.DataFrame({0: series_category,
                                        1: series_vendor,
                                        2: series_prod,
                                        3: series_version,
                                        4: series_signature}, columns=None)
                self.pd_train_cms = pd.concat([self.pd_train_cms, temp_df])
                self.pd_train_cms.to_csv(self.train_cms_in,
                                         sep='@', encoding='utf-8', header=False, index=False, quoting=csv.QUOTE_NONE)
                self.utility.print_message(OK, 'Add OS train data: {} items.'.format(len(train[CMS])))

            # Show graph.
            # self.show_graph(target, graph)
        except Exception as e:
            self.utility.print_exception(e, '{}'.format(e.args))
