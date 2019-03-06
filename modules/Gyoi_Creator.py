#!/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import configparser
import collections
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

        self.target_dir = os.path.join(self.root_path, config['Creator']['target_dir'])
        self.prohibit_ext_list = config['Creator']['prohibit_ext'].split('@')
        self.save_file = config['Creator']['result_file'].replace('*', datetime.now().strftime('%Y%m%d%H%M%S'))
        self.save_path = os.path.join(self.full_path, self.save_file)
        self.header = str(config['Creator']['header']).split('@')
        self.score_table_path = os.path.join(self.full_path, config['Exploit']['data_path'])

        # Load score table.
        self.pd_score_table = pd.read_csv(os.path.join(self.score_table_path, config['Creator']['score_table']))

        # Count directory number.
        self.offset_layer_num, _ = self.count_dir_layer(self.target_dir)

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
                dir_count, _ = self.count_dir_layer(root)
                record.insert(3, dir_count - self.offset_layer_num)
                record.insert(4, file_count)
                record.insert(5, list(set(ext_list)))
                record.insert(6, collections.Counter(ext_list))
                report.append(record)
                base_index += 1

            # Save extracted information.
            pd.DataFrame(report).to_csv(self.save_path, mode='a', header=False, index=False)
        else:
            print('Error: Path or file is not found.\n=> {}'.format(target_dir))
            sys.exit(1)
        return report

    # Calculate score of node.
    def calc_score(self, ext_type, ext_counts):
        score = 0.0
        count = 0
        for ext in ext_type:
            # Get defined score from score table.
            pd_score = self.pd_score_table[self.pd_score_table['extension'] == ext.lower()]
            ext_count = ext_counts[ext]
            count += ext_count
            if len(pd_score) != 0:
                # Calculate score.
                score += pd_score['probability'].values[0] * ext_count
        return score / count

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
                    # Calculate score.
                    score = 0.0
                    if len(record[5]) != 0:
                        score = self.calc_score(record[5], record[6])

                    # Add new node.
                    dir_pool[label] = node_index
                    graph.add_node(node_index, ext_type=record[5], ext_count=record[6], score=score)
                    node_index += 1

                    # Create edge that connecting two nodes.
                    if parent_dir != '' and label != parent_dir:
                        graph.add_edge(dir_pool[parent_dir], dir_pool[label])
                        print('Create edge node.{} <-> node.{}'.format(dir_pool[parent_dir], dir_pool[label]))
        return graph

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
                record = self.execute_grep(target, os.path.join(self.target_dir, target))
                graph = self.create_network(record)

                # Show graph.
                print('Creating network image...')
                plt.figure(figsize=(10, 10))
                nx.draw_networkx(graph)
                plt.axis('off')
                file_name = os.path.join(self.full_path, target + '.png')
                plt.savefig(file_name)
                plt.show()
        except Exception as e:
            print('{}'.format(e.args))


if __name__ == '__main__':
    # Create train data.
    creator = Creator()
    creator.extract_file_structure()
    print('finish!!')
