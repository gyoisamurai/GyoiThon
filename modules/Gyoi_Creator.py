#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import zipfile
import tarfile
import codecs
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


class Creator:
    def __init__(self, utility):
        # Read config.ini.
        self.utility = utility
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        self.compress_dir = os.path.join(self.root_path, config['Creator']['compress_dir'])
        self.signature_dir = os.path.join(self.root_path, config['Creator']['signature_dir'])
        self.tmp_sig_product = os.path.join(self.signature_dir, config['Creator']['created_prd_sig'])
        self.tmp_sig_def_content = os.path.join(self.signature_dir, config['Creator']['created_def_sig'])
        self.tmp_train_in = os.path.join(self.signature_dir, config['Creator']['created_train'])
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
    def return_score(self, file_name):
        _, ext = os.path.splitext(file_name)
        pd_score = self.pd_score_table[self.pd_score_table['extension'] == ext[1:].lower()]
        score = 0.0
        if len(pd_score) > 0:
            score = pd_score['probability'].values[0]
        return score

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

    # Exchange path to signature/train data.
    def transform_path_sig(self, category, vendor, name, version, target_path):
        sig_product = category + '@' + vendor + '@' + name + '@' + version + '@(' + target_path + ')\n'
        sig_cotent = category + '@' + vendor + '@' + name + '@' + version + '@' + target_path + '@*@*@0\n'
        train = category + '@' + vendor + '@' + name + '@' + version + '@(' + target_path + ')\n'
        return sig_product, sig_cotent, train

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
            fout_product = codecs.open(self.tmp_sig_product.replace('*', target_name), 'a', encoding='utf-8')
            fout_default_content = codecs.open(self.tmp_sig_def_content.replace('*', target_name), 'a', encoding='utf-8')
            fout_train = codecs.open(self.tmp_train_in.replace('*', target_name), 'a', encoding='utf-8')
            s_file = []
            s_path = []
            train = []
            for idx, item in enumerate(open_paths):
                # Create signature.
                files = graph.nodes[item[0]]['files']
                if item[2] == 1.0 and len(files) > 0:
                    # Create path type signature.
                    sig_path = item[1].replace('\\', '/')
                    if sig_path.endswith('/') is False:
                        sig_path += '/'
                    _, s_path_cont, t_path = self.transform_path_sig(category, vendor, prod_name, prod_ver, sig_path)

                    # Calculate score of each file.
                    s_file_tmp = []
                    train_tmp = []
                    total_file_score = 0
                    for file in files:
                        file_path = sig_path + file
                        s1, _, t1 = self.transform_path_sig(category, vendor, prod_name, prod_ver, file_path)
                        s_file_tmp.append(s1)
                        train_tmp.append(t1)
                        total_file_score += self.return_score(file)

                    # Add item to signature or train data.
                    if total_file_score / len(files) == 1.0:
                        s_file.extend(s_file_tmp)
                        s_path.append(s_path_cont)
                        self.utility.print_message(OK, '{}/{} Create signature: {}.'.format(idx + 1,
                                                                                            len(open_paths),
                                                                                            sig_path))
                    else:
                        train.append(t_path)
                        train.extend(train_tmp)
                        self.utility.print_message(OK, '{}/{} Create train data: {}.'.format(idx + 1,
                                                                                             len(open_paths),
                                                                                             sig_path))
                # Create train data.
                elif item[2] >= self.threshold:
                    train_path = item[1].replace('\\', '/')
                    if train_path.endswith('/') is False:
                        train_path += '/'
                    _, _, train_data = self.transform_path_sig(category, vendor, prod_name, prod_ver, train_path)
                    train.append(train_data)
                    for file in files:
                        train_file = item[1].replace('\\', '/') + file
                        _, _, train_data = self.transform_path_sig(category, vendor, prod_name, prod_ver, train_file)
                        train.append(train_data)

            # Write signature/train data to local files.
            fout_default_content.writelines(list(set(s_path)))
            self.utility.print_message(OK, 'Create Path signature: {} items.'.format(len(s_path)))
            fout_product.writelines(list(set(s_file)))
            self.utility.print_message(OK, 'Create File signature: {} items.'.format(len(s_file)))
            fout_train.writelines(list(set(train)))
            self.utility.print_message(OK, 'Create Train data: {} items.'.format(len(train)))
            fout_product.close()
            fout_default_content.close()
            fout_train.close()

            # Show graph.
            # self.show_graph(target, graph)
        except Exception as e:
            self.utility.print_exception(e, '{}'.format(e.args))
