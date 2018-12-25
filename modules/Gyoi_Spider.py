#!/usr/bin/python
# coding:utf-8
import time
import codecs
import scrapy
from scrapy.http import Request


class SimpleSpider(scrapy.Spider):
    name = 'simple_spider'

    def __init__(self, category=None, *args, **kwargs):
        super(SimpleSpider, self).__init__(*args, **kwargs)
        self.start_urls = getattr(self, 'target_url', None)
        self.allowed_domains = [getattr(self, 'allow_domain', None)]
        self.concurrent = int(getattr(self, 'concurrent', None))
        self.depth_limit = int(getattr(self, 'depth_limit', None))
        self.delay_time = float(getattr(self, 'delay', None))
        self.store_path = getattr(self, 'store_path', None)
        self.proxy_server = getattr(self, 'proxy_server', None)
        self.user_agent = getattr(self, 'user_agent', None)
        self.encoding = getattr(self, 'encoding', None)
        self.custom_settings = {
            'CONCURRENT_REQUESTS': self.concurrent,
            'CONCURRENT_REQUESTS_PER_DOMAIN': self.concurrent,
            'DEPTH_LIMIT ': self.depth_limit,
            'DOWNLOAD_DELAY': self.delay_time,
            'ROBOTSTXT_OBEY': True,
            'USER_AGENT': self.user_agent,
            'HTTPCACHE_ENABLED': True,
            'HTTPCACHE_EXPIRATION_SECS': 60 * 60 * 24,
            'HTTPCACHE_DIR': self.store_path,
            'FEED_EXPORT_ENCODING': self.encoding
        }
        self.fout = codecs.open(self.store_path, 'a', encoding=self.encoding)

    def start_requests(self):
        url = self.start_urls

        # Set proxy server.
        if self.proxy_server != '':
            proxy = {'proxy': self.proxy_server}
            yield Request(url, self.parse, meta=proxy)
        else:
            yield Request(url, self.parse)

        # yield Request(url, self.parse)

    def parse(self, response):
        self.fout.write(response.body.decode(self.encoding))
        for href in response.css('a::attr(href)'):
            full_url = response.urljoin(href.extract())
            time.sleep(self.delay_time)

            # Set proxy server.
            if self.proxy_server != '':
                proxy = {'proxy': self.proxy_server}
                yield scrapy.Request(full_url, callback=self.parse_item, meta=proxy)
            else:
                yield scrapy.Request(full_url, callback=self.parse_item)

    def parse_item(self, response):
        urls = []
        self.fout.write(response.body.decode(self.encoding))
        for href in response.css('a::attr(href)'):
            full_url = response.urljoin(href.extract())
            urls.append(full_url)
        yield {
            'urls': urls,
        }
