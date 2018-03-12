#!/bin/env python
# -*- coding: utf-8 -*-
import sys
import math
import re


class NaiveBayes:
    def __init__(self):
        self.vocabularies = set()
        self.word_count = {}
        self.category_count = {}

    # カテゴリ単位でカウント(Bag-of-Wordsの作成)
    def word_count_up(self, word, category):
        self.word_count.setdefault(category, {})
        self.word_count[category].setdefault(word, 0)
        self.word_count[category][word] += 1
        self.vocabularies.add(word)

    # カテゴリ数のカウント
    def category_count_up(self, category):
        self.category_count.setdefault(category, 0)
        self.category_count[category] += 1

    # キーワードとカテゴリを基に学習
    def train(self, doc, category):
        # カテゴリ単位でカウントする
        self.word_count_up(doc, category)
        # カテゴリ数をカウントする
        self.category_count_up(category)

    # ベイズ定理における事前確率の計算
    def prior_prob(self, category):
        num_of_categories = sum(self.category_count.values())
        num_of_docs_of_the_category = self.category_count[category]
        return float(num_of_docs_of_the_category) / float(num_of_categories)

    # キーワードの出現数をカウント
    def num_of_appearance(self, word, category):
        word_count = 0
        keyword_list = []
        for key_item in self.word_count[category]:
            list_match = re.findall(key_item, word)
            if len(list_match) != 0:
                word_count += 1
                # keyword_list.append(key_item)
                keyword_list.append(list_match)
        prob = float(word_count) / float(len(self.word_count[category]))
        return word_count, keyword_list, prob

    # ベイズ定理の計算
    def word_prob(self, word, category):
        numerator, keyword_list, temp_prob = self.num_of_appearance(word, category)
        # ラプラス・スムージング
        numerator += 1
        denominator = sum(self.word_count[category].values()) + len(self.vocabularies)
        prob = float(numerator) / float(denominator)
        return prob, keyword_list, temp_prob

    # 予測したいキーワードが各カテゴリに含まれる確率を計算
    def score(self, word, category):
        score = math.log(self.prior_prob(category))
        prob, keyword_list, temp_prob = self.word_prob(word, category)
        score += math.log(prob)
        return score, prob, keyword_list, temp_prob

    # 分類の実行
    def classify(self, doc):
        best_guessed_category = None
        max_prob_before = -sys.maxsize
        keyword_list = []
        classified_list = []

        # カテゴリ単位で類似度のスコアを算出
        for category in self.category_count.keys():
            score, total_prob, feature_list, category_prob = self.score(doc, category)
            classified_list.append([category, float(total_prob), feature_list])

            # 予測したい文章を、スコアの最も大きいカテゴリに分類する
            if score > max_prob_before:
                max_prob_before = score
                best_guessed_category = category
                keyword_list = feature_list
                classified_prob = total_prob
        return best_guessed_category, float(classified_prob), keyword_list, classified_list
