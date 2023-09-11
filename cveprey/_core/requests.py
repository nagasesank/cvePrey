from genericpath import exists
from typing import Any
from urllib.request import Request, urlopen
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
import time, ssl, urllib3, requests
from .. _utils.dec import *


class _CustomHttpAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=self.ssl_context)


class CVENetTools(object):

    @staticmethod
    def _getLegacySession():
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
        session = requests.session()
        session.mount('https://', _CustomHttpAdapter(ctx))
        return session
    
    @staticmethod
    def getGecko(url:str) -> Any:
        execPath = "/opt/gecko/geckodriver"
        if exists(execPath):
            options = Options()
            options.add_argument("--headless")
            driver = webdriver.Firefox(options=options, executable_path=execPath)
            driver.get(url)
            time.sleep(10)
            html = driver.page_source
            driver.quit()
            return html
        else:
            print("geckodriver is not found under %s" % execPath)

    @staticmethod
    def geckoDriver() -> Any:
        execPath = "/opt/gecko/geckodriver"
        if exists(execPath):
            service = Service(execPath)
            options = Options()
            options.add_argument("--headless")
            driver = webdriver.Firefox(options=options, service=service)
            return driver
        else:
            print("geckodriver is not found under %s" % execPath)

    @staticmethod
    def get_old(url: str) -> Any:
        '''
        Request the URL and return the Response
        params:
            url: Type str
            rtype: str
        '''
        request = Request(
            url=url, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36'}
        )
        with urlopen(request) as response:
            html = response.read()
            try:
                resp = html.decode('utf-8')
            except UnicodeDecodeError as e:
                resp = html
        return resp

    @classmethod
    @timeTaken
    def get(cls, url: str, headers=None, verify=True) -> str:
        '''
        Request the URL and return the Response
        params:
            url: Type str
            rtype: str
        '''
        if headers != None:
            request = cls._getLegacySession()
            request.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36'})
            request.headers.update(headers)
            response = request.get(url, verify=verify)
        else:
            request = cls._getLegacySession()
            request.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36'})
            response = request.get(url, verify=verify)
        
        return response.text
    
    @classmethod
    @timeTaken
    def post(cls, url: str, data: dict, headers=None ,verify=True) -> str:
        '''
        Post a request and return a response
        params:
            url: Type str
            data: dict
            rtype: str
        '''
        if headers != None:
            request = cls._getLegacySession()
            request.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36'})
            request.headers.update(headers)
            response = request.post(url, data=data, verify=verify)
        else:
            request = cls._getLegacySession()
            request.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36'})
            response = request.post(url, data=data, verify=verify)
        
        return response.text
