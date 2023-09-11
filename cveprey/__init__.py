from ._advisories import *
from . import _core

class CVE():
    r'''
    CVE Deamon
    Holds the CVE and retrieve the corresponding Information from target Database
    Usefull for Non-NVD CVE's
    params: 
        cve_id : Type str
    '''
    def __init__(self, cve_id: str) -> None:
        self.cve_id = cve_id

    def get_nvd_data(self) -> None:
        self.nvd_data = _core.NVDScraper(self.cve_id)

    def get_mitre_data(self) -> None:
        self.mitre_data = _core.MitreScraper(self.cve_id)

    def __repr__(self) -> str:
        return f"<CVE({self.cve_id}) **cvePrey>"


class mitreCVESearch():
    r'''
    Collects information from MITRE
    params:
        keyword: str
    '''
    def __init__(self, keyword: str):
        self.cve_list = self._cveSearch(keyword)
    
    def _cveSearch(self, keyword: str):
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}"
        response = _core.CVENetTools.get(url)
        cve_list = _core.lhtml.fromstring(response).xpath('//div[@id="TableWithRules"]/table/tbody/tr//a[contains(text(), "CVE")]/text()')
        
        return list(set(cve_list))
    
    def __repr__(self) -> str:
        return f"<class mitreCVESearch **cvePrey>"


class nvdCVESearch():
    r'''
    Collects information from NVD
    params:
        keyword: str
    '''
    def __init__(self, keyword: str):
        self.cve_list = self._cveSearch(keyword)
    
    def _cveSearch(self, keyword: str):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
        response = _core.CVENetTools.get(url)
        
        return response
    
    def __repr__(self) -> str:
        return f"<class nvdCVESearch **cvePrey>"

