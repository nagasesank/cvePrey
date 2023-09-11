from .. import _core
import re, json

class AdobeSecurityAdvisories():
    r'''
    Extract Advisory link from Adobe Security Advisories page
    params:
        cve: str
    '''
    def __init__(self, cve: str):
        self.cve = cve
        self._def_product = "Adobe Reader"
        url = "https://helpx.adobe.com/security/security-bulletin.html"
        self.parsed_content = _core.lhtml.fromstring(_core.CVENetTools.get(url))

    @property
    def getProduct(self):
        try:
            matched_table = self.parsed_content.xpath(f'//div[contains(.//h2/text(), "{self._def_product}")]/following::div/table')[0]
            links = list(set(map(lambda x: x if "http" in x else f"https://helpx.adobe.com{x}",matched_table.xpath('.//tr[./td]//a/@href'))))
            self.adv_link = [link for link in links if self.cve in _core.CVENetTools.get(link)]
        except Exception as e:
            print(e)
            pass

    @getProduct.setter
    def getProduct(self, value):
        self._def_product = value
    
class AdobeAdvisories():
    r'''
    '''
    def __init__(self, cve: str, url: str):
        pass