from .. import _core
import re, json

ADV_URL = '''https://securitycontact.manageengine.com/publiccve?from=1&limit=25&criteria=CVE_ID.contains(%22{cve}%22)%26%26For_product_search%3D%3D0'''

class Zoho():
    r'''
    Collects CVE information from Zoho Advisories and process its properties
    params:
        cve: str

    properties:
        title
        versions
        upgrade_link
    '''
    def __init__(self, cve:str) -> None:
        url = ADV_URL.format(cve=cve)
        headers = {'Origin': 'https://www.manageengine.com', 'Connection': 'keep-alive'}
        parsed_data = _core.CVENetTools.get(url, headers=headers)
        self.adv_url = json.loads(parsed_data)['data'][0]['CVE_Details_Link']['value']
        self.parsed_data = _core.lhtml.fromstring(_core.CVENetTools.get(self.adv_url))

    @property
    def title(self) -> str:
        return self.parsed_data.xpath('.//h2[contains(@class, "pB0")]/text()')[0]
    
    @property
    def upgrade_link(self) -> str:
        return self.parsed_data.xpath('.//li[contains(./text(), "latest")]//*/@href')
    
    @property
    def affected_versions(self) -> str:
        versions = {}
        products =  self.parsed_data.xpath('.//div[contains(@class, "sec-pTB")]//table/tbody/tr')
        for name in products:
            versions[name.xpath('./td/text()')[0]] = ",".join(name.xpath('./td/text()')[1:3])

        return versions