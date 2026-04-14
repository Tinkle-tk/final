BOT_NAME = 'ics_spider'

SPIDER_MODULES = ['ics_spider.spiders']
NEWSPIDER_MODULE = 'ics_spider.spiders'

ROBOTSTXT_OBEY = False
DOWNLOAD_DELAY = 1
CONCURRENT_REQUESTS_PER_DOMAIN = 8

DEFAULT_REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; ICS-Vuln-KB/1.0)',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
}

ITEM_PIPELINES = {}
