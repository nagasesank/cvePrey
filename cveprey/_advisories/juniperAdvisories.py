from .. import _core
import re


class juniperAdvisories():
    r'''
    Collects CVE information from Juniper Advisory and process its properties
    params:
        url: str

    properties:
        title
        versions_raw
    '''
    def __init__(self, url: str):
        self.raw_content = _core.CVENetTools.getGecko(url)
        self.parsed_object = _core.lhtml.fromstring(self.raw_content)

    @property
    def title(self):
        return self.parsed_object.xpath('//div[@class="titleSection"]/p/text()')[0]

    @property
    def versions_raw(self):
        regex = re.compile(r'>(^\d[\d\.A-Za-z,\s;]+|[^Jj][A-Za-z\s\d\.-]+[\d\.]+[FIXBAR][\d\.]+[-]?[SD]?[A-Za-z\d\.\-\s,;]+)<')
        versions = regex.findall(self.raw_content)
        for version in versions:
            yield {

            }

    @property
    def affected_products(self):
        products = self.parsed_object.xpath('//div[contains(@class, "afftedProd")]/a/text()')
        return products
    
    @property
    def prs(self):
        r'''
        get problem report links
        '''
        links = self.parsed_object.xpath('//a[contains(@href, "problemreport")]/@href')
        return links
    

class juniperCEC(object):
    def __init__(self, cve:str):
        cve = ''

    def _none():
        pass

    def cveSearch(self, cve:str):
        pass