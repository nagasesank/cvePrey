from .. import _core
import re

class NVDScraper():
    r'''
    Collects CVE information from NVD and process its properties
    params:
        cve: str

    properties:
        cpe_info
        family
        product
        affected_family
        description
        adv_links
        published_on
        last_modified_on
        vendor
        cwe
        cvss_metrics
        get_json_data
    '''
    def __repr__(self) -> str:
        return "<class cveprey.scrapers.NVDScraper *scrapers **cvePrey>"
        
    def __init__(self, cve: str):
        self.url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        self.response = _core.CVENetTools.get(self.url)
        self.parsed_object = _core.lhtml.fromstring(self.response)

    @property
    def cpe_info(self):
        return list(set(re.findall(r'(cpe:\d\.\d:[a-z][:A-Za-z\.\-\_\d\*]+)', self.response)))

    @property
    def family(self):
        return list(set([__.split(':')[3] for __ in self.cpe_info if 'cpe:2.3:o' in __]))

    @property
    def product(self):
        return list(set([__.split(':')[4] for __ in self.cpe_info if 'cpe:2.3:h' in __]))

    @property
    def affected_family(self):
        return list(set([__.split(':')[4] for __ in self.cpe_info if f'cpe:2.3:o' in __]))

    @property
    def description(self):
        return "".join(self.parsed_object.xpath('//p[@data-testid="vuln-description"]/text()'))

    @property
    def adv_links(self):
        return self.parsed_object.xpath('//table[@data-testid="vuln-hyperlinks-table"]//tbody//a/text()')

    @property
    def published_on(self):
        return "".join(self.parsed_object.xpath('//span[@data-testid="vuln-published-on"]/text()'))

    @property
    def last_modified_on(self):
        return "".join(self.parsed_object.xpath('//span[@data-testid="vuln-last-modified-on"]/text()'))

    @property
    def vendor(self):
        return self.parsed_object.xpath('//span[@data-testid="vuln-current-description-source"]/text()')

    @property
    def cwe(self):
        try:
            cwes = [
                {'CWE-ID': cwe.xpath('./td/a')[0].text, 'CWE-Name': cwe.xpath('./td/text()')[2]} for cwe in self.parsed_object.xpath('//tr[contains(@data-testid, "vuln-CWEs-row")]')]
            return cwes
        except Exception as e:
            return "NVD-CWE-noinfo"

    @property
    def cvss_metrics(self):
        return {
            'NIST': "".join(self.parsed_object.xpath('//a[@data-testid="vuln-cvss3-panel-score"]/text()')),
            'CNA': "".join(self.parsed_object.xpath('//a[@data-testid="vuln-cvss3-cna-panel-score"]/text()'))
        }

    @property
    def get_json_data(self):
        return [
            self.url,
            self.response,
            self.parsed_object,
            self.description,
            self.vendor,
            self.cpe_info,
            self.cvss_metrics,
            self.cwe,
            self.adv_links,
            self.last_modified_on,
            self.published_on,
            self.family,
            self.product
        ]


class MitreScraper():
    r'''
    Collects CVE information from MITRE and process its properties
    params:
        cve: str

    properties:
        nvd_links
        description
        adv_links
        vendor
    '''
    def __init__(self, cve: str):
        self.url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
        self.response = _core.CVENetTools.get(self.url)
        self.parsed_object = _core.lhtml.fromstring(self.response)

    @property
    def nvd_links(self):
        return self.parsed_object.xpath('//div[@id="GeneratedTable"]/table/tbody/tr//td[@class="larger"]/a/text()')

    @property
    def description(self):
        return self.parsed_object.xpath('//div[@id="GeneratedTable"]/table/tbody/tr[4]/td/text()')

    @property
    def adv_links(self):
        return self.parsed_object.xpath('//div[@id="GeneratedTable"]/table/tbody/tr/td/ul/li/a/@href')

    @property
    def vendor(self):
        return self.parsed_object.xpath('//div[@id="GeneratedTable"]/table/tbody/tr[9]/td/text()')
