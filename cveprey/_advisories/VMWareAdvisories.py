from .. import _core
import re, json

HOST = "https://www.vmware.com"

class VMWareAdvisories():
    r'''
    Extract details from VMWare Advisories
    '''
    def __init__(self, cve:str) -> None:
        self.cve_id = cve
        self.adv_raw = self.get_all_list["data"]
        self.parsed_content = _core.lhtml.fromstring(_core.CVENetTools.get(self.adv_url))

    @property
    def get_all_list(self) -> dict:
        adv_url = f"{HOST}/bin/vmware/getmodernizeadvisorieslist?resourcePath=/content/vmware/vmware-published-sites/us/security/advisories"
        adv_raw = json.loads(_core.CVENetTools.get(adv_url))
        return adv_raw

    @property
    def adv_url(self) -> list:
        for adv in self.adv_raw:
            if self.cve_id in adv['Synopsis']:
                return HOST+adv['AdvisoryURL']
    
    @property
    def adv_id(self) -> list:
        for adv in self.adv_raw:
            if self.cve_id in adv['Synopsis']:
                return adv['AdvisoryID']
            
    @property
    def affected_products(self):
        table = self.parsed_content.xpath('//section[@class="response-matrix"]//table[@class="table"]')[0]
        products = table.xpath('.//tr[@class="tr"]/td[@data-th="Product"]/*/text()')
        return set(products)

    @property
    def affected_versions(self):
        versions = {}
        table = self.parsed_content.xpath('//section[@class="response-matrix"]//table[@class="table"]')[0]
        for row in table.xpath('.//tr'):
            versions[row.xpath('./td[@data-th="Product"]/*/text()')[0].strip()] = row.xpath('./td[@data-th="Version"]/*/text()')
