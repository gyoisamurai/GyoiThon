#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import zipfile
import tarfile
import configparser
import collections
import statistics
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from datetime import datetime


class Creator:
    def __init__(self):
        # Read config.ini.
        config = configparser.ConfigParser()
        self.file_name = os.path.basename(__file__)
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.root_path = os.path.join(self.full_path, '../')
        config.read(os.path.join(self.root_path, 'config.ini'))

        self.compress_dir = os.path.join(self.root_path, config['Creator']['compress_dir'])
        self.target_dir = os.path.join(self.root_path, config['Creator']['target_dir'])
        self.prohibit_ext_list = config['Creator']['prohibit_ext'].split('@')
        self.save_file = config['Creator']['result_file'].replace('*', datetime.now().strftime('%Y%m%d%H%M%S'))
        self.save_path = os.path.join(self.full_path, self.save_file)
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
        self.is_dir_existance(self.target_dir)
        self.is_dir_existance(self.score_table)

        # Load score table.
        self.pd_score_table = pd.read_csv(self.score_table)

    # Check necessary directory.
    def is_dir_existance(self, target_dir):
        if os.path.exists(self.compress_dir) is False:
            print('Directory is not found: {}'.format(target_dir))
            sys.exit(1)

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
                    print('Check file : {}/{}'.format(root.replace(self.target_dir, ''), file))
                    _, ext = os.path.splitext(file)
                    if ext[1:] not in self.prohibit_ext_list:
                        # Count file number and target extension.
                        file_count += 1
                        ext_list.append(ext[1:])

                # Save information each directory.
                record = []
                record.insert(0, base_index)
                record.insert(1, target_product)
                record.insert(2, root.replace(self.target_dir, ''))
                record.insert(3, list(set(ext_list)))
                record.insert(4, collections.Counter(ext_list))
                record.insert(5, list(set(files)))
                report.append(record)
                base_index += 1

            # Save extracted information.
            pd.DataFrame(report).to_csv(self.save_path, mode='a', header=False, index=False)
        else:
            print('Error: Path or file is not found.\n=> {}'.format(target_dir))
            sys.exit(1)
        return report

    # Show graph.
    def show_graph(self, target, graph):
        print('Creating network image...')
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
            print('{}/{} Analyzing "{}"'.format(index + 1, len(records), record[2]))
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
                                   rank=rank)
                    node_index += 1

                    # Create edge that connecting two nodes.
                    if parent_dir != '' and label != parent_dir:
                        graph.add_edge(dir_pool[parent_dir], dir_pool[label])
                        print('Create edge node.{} <-> node.{}'.format(dir_pool[parent_dir], dir_pool[label]))
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
    def decompress_file(self):
        # Extract path and file name from target directory.
        target_list = os.listdir(self.compress_dir)

        for target in target_list:
            # Create extraction directory name.
            extract_dir_name = ''
            if '.tar' in os.path.splitext(target)[0]:
                extract_dir_name = os.path.splitext(target)[0]
            else:
                extract_dir_name = os.path.splitext(target)[0].replace('.tar', '')
            extract_path = os.path.join(self.target_dir, extract_dir_name)

            try:
                # Execute extraction.
                target_path = os.path.join(self.compress_dir, target)
                if '.tar' in target:
                    print('Decompress {}'.format(target))
                    self.extract_tar(target_path, extract_path)
                elif '.zip' in target:
                    print('Decompress {}'.format(target))
                    self.extract_zip(target_path, extract_path)
            except Exception as e:
                print('{}'.format(e.args))

    # Explore open path.
    def explore_open_path(self, graph, all_paths):
        open_paths = []
        for idx, path in enumerate(all_paths):
            tmp_open_paths = []
            close_path_index = len(path) - 1
            print('{}/{} Explore path: {}'.format(idx + 1, len(all_paths), path))
            for idx2, node_index in enumerate(path[::-1]):
                print('Checking turn inside node.{}:{}'.format(node_index, graph.nodes[node_index]['path']))

                # Add open path.
                if graph.nodes[node_index]['rank'] == 1.0:
                    print('Add node {} to open path list.'.format(node_index))
                    tmp_open_paths.append([node_index, graph.nodes[node_index]['path']])
                    close_path_index = len(path) - idx2 - 2
                # Execute "Othello".
                elif 0 < (len(path) - idx2 - 1) < len(path) - 1:
                    # Extract ranks of parent and child node.
                    parent_node_rank = graph.nodes[path[len(path) - idx2 - 2]]['rank']
                    child_node_rank = graph.nodes[path[len(path) - idx2]]['rank']

                    # Checking turn inside the node rank.
                    if parent_node_rank == 1.0 and child_node_rank == 1.0:
                        print('Turned inside rank={} -> 1.0.'.format(graph.nodes[node_index]['rank']))
                        print('Add node {} to open path list.'.format(node_index))
                        tmp_open_paths.append([node_index, graph.nodes[node_index]['path']])
                        graph.nodes[node_index]['rank'] = 1.0
                        close_path_index = len(path) - idx2 - 2
                    else:
                        if close_path_index < len(path) - idx2 - 1:
                            close_path_index = len(path) - idx2 - 1
                else:
                    if close_path_index < len(path) - idx2 - 1:
                        close_path_index = len(path) - idx2 - 1

            # Cut unnecessary path (root path -> open path).
            if close_path_index != -1:
                for tmp_path in tmp_open_paths:
                    delete_seq = len(graph.nodes[path[close_path_index]]['path'])
                    open_paths.append([tmp_path[0], tmp_path[1][delete_seq:]])

        return list(map(list, set(map(tuple, open_paths))))

    # Main control.
    def extract_file_structure(self):
        # Decompress compressed package file.
        # self.decompress_file()

        # Extract path and file name from target directory.
        target_list = os.listdir(self.target_dir)

        # Create report header.
        pd.DataFrame([], columns=self.header).to_csv(self.save_path, mode='w', index=False)

        # Extract file structures.
        try:
            for target in target_list:
                # Extract file path each products.
                record = self.execute_grep(target, os.path.join(self.target_dir, target))
                graph = self.create_network(record)

                # Extract all paths to end node from root node.
                all_paths = []
                node_num = len(graph._adj)
                for end_node_idx in range(node_num):
                    print('{}/{} Analyzing node={}'.format(end_node_idx + 1, node_num, end_node_idx))
                    if len(graph._adj[end_node_idx]) == 0:
                        for path in nx.all_simple_paths(graph, source=0, target=end_node_idx):
                            print('Extract path that source={} <-> target={}, path={}'.format(0, end_node_idx, path))
                            all_paths.append(path)

                # Execute "Othello".
                open_paths = []
                for try_num in range(self.try_othello_num):
                    print('{}/{} Execute "Othello".'.format(try_num + 1, self.try_othello_num))
                    open_paths.extend(self.explore_open_path(graph, all_paths))

                # Create signature.
                open_paths = list(map(list, set(map(tuple, open_paths))))
                signature_list = []
                for item in open_paths:
                    files = graph.nodes[item[0]]['files']
                    signature_list.append(item[1].replace('\\', '/'))
                    for file in files:
                        signature_list.append(os.path.join(item[1], file))
                print()

                # Show graph.
                # self.show_graph(target, graph)
        except Exception as e:
            print('{}'.format(e.args))


if __name__ == '__main__':
    # Create train data.
    creator = Creator()
    creator.extract_file_structure()
    print('finish!!')
