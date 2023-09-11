from .. import _core
import re, json

class splunkAdvisories(object):
    r'''
    Retrive the CVE information from the Splunk Advisory
    '''
    def __init__(self, url:str) -> None:
        self.url = url
        content = _core.CVENetTools.get(url)
        self.parsed_content = _core.lhtml.fromstring(content.encode('utf-8'))

    @property
    def title(self) -> str:
        return self.parsed_content.xpath('//div[@class="advisory-title"]/*/text()')[0]
    
    @property
    def adv_id(self) -> str:
        ad_id = _core.re.findall(r"/(SVD.*)", self.url)[0]
        return ad_id
    
    @property
    def versions(self):
        version_table = self.parsed_content.xpath('//table[@id="advisory-table"]//tr[@class="advisory-tr"]')
        versions = {}
        for row in version_table:
            versions[row.xpath('.//td[@label="Product"]/text()')[0]] = []

        for row in version_table:
            versions[row.xpath('.//td[@label="Product"]/text()')[0]].append("".join(row.xpath('.//td[@label="Affected Version"]/text()')))

        return versions