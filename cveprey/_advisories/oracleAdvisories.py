from .. import _core
import re, time as _time


class oraclePatches():
    '''
    get the patch for a version
    '''        
    def _getPatchstrings(self, cve: str, patch_link: str):
        r'''
        get patch string's of CVE from patch page
        '''
        self.driver.get(patch_link)
        content = self.driver.page_source
        root = _core.lhtml.fromstring(content)
        patch_string = root.xpath(f'//table[@rules="all"]//tr[.//*[contains(./text(),"{cve}")]]')
        patch_string = [" ".join(" ".join(i.xpath('.//text()')).split('\n')) for i in patch_string]
        return patch_string

    def _init_patch_session(self, username: str, password: str, login_url="https://support.oracle.com/epmos/faces/Dashboard"):
        r'''
        initialize oracle support session
        '''
        self.driver = _core.CVENetTools.geckoDriver()
        self.driver_state = True
        self.driver.get(login_url)
        _time.sleep(10)
        try:
            self.driver.find_element("id", "sso_username").send_keys(username)
            self.driver.find_element("id", "ssopassword").send_keys(password)
            self.driver.find_element("id", "signin_button").click()
        except Exception:
            print("Using Active Gecko Session")


class oracleAdvisories():
    r'''
    Collects CVE information from Oracle Advisories and process its properties
    params:
        cve: str
        url: str

    properties:
        title
        versions
    '''
    def __init__(self, adv_urls: list, cve: str=None, comp=None) -> None:
        self.versions = {}
        self.patch_links = {}
        self._cve = cve
        self.driver_state = False
        for url in adv_urls:
            self.raw_content = _core.CVENetTools.get(url)
            self.root = _core.lhtml.fromstring(self.raw_content)
            if cve != None:
                self._getIndexTables(cve, comp=comp)

    def _getIndexTables(self, cve: str, comp=None) -> None:
        '''
        get the tables names from advisory and grabs affected versions
        '''
        self.table_labels = self.root.xpath('//*[contains(text(), "Risk Matrix")]/text()')[::-1]
        # + Bug Identified by Internal Testing team and updated to work on older advisories
        self.table_labels = ["".join(_core.re.findall(r"(^Oracle.*Risk Matrix$)", string)) for string in self.table_labels if "".join(_core.re.findall(r"(^Oracle.*Risk Matrix$)", string)) != '']
        # if len(self.table_labels) < 1:
        #     self.table_labels = [
        #         re.findall(r"(Appendix\s*-\s*)?(.*)( Executive)", val)[0][1]+" Risk Matrix" if "Executive Summary" in val 
        #                 else re.findall(r"(Appendix\s*-\s*)?(.*)", val)[0][1]+" Risk Matrix"
        #                 for val in table_lables_2]
        # if len(self.table_labels) < 1:
        #     self.table_labels = [name.xpath('./text()')[0] for name in self.root.xpath('//h4[contains(text(), "Risk Matrix")]') if name.xpath('./text()')[0].startswith('Oracle')][::-1]
        for table in self.table_labels:
            # self.header = list(map(lambda x: "".join(x.xpath('./text()')), list(self.root.xpath(f'//*[contains(text(), "{table}")]/following::div/div/table[@class="otable-w2"]/thead/tr')[0])))
            # match = self.root.xpath(f'//*[contains(./text(), "{table}")]/following-sibling::div/div/table[@class="otable-w2"]//tbody//tr[th[@class="otable-col-sticky" and contains(.//text(), "{cve}")]]')
            match = self.root.xpath(f'//div[.//table[@class="otable-w2"] and ./preceding::*[contains(.//text(), "{table}")] and ./div/table//tbody//tr[th[@class="otable-col-sticky" and contains(.//text(), "{cve}")]]]')
            if len(match)>0:
                match = match[0]
                rows = match.xpath(f'.//div/table//tbody//tr[th[@class="otable-col-sticky" and contains(.//text(), "{cve}")]]')
                for row in rows:
                    rect_string = _core.re.findall(r'Oracle (.*) Risk Matrix', table)[0]
                    self.patch_links[rect_string] = "".join(self.root.xpath(f'//tbody//tr[contains(.//td//text(), "{rect_string}")]//a/@href[contains(., "support.oracle.com")]'))
                    if comp != None:
                        component = [ver.strip() for ver in re.findall(r'([\d\.A-Z\sa-z:-]+)', row.xpath('./td//text()')[1])][0]
                        if comp.lower() not in component.lower():
                            continue
                    
                    if len(re.findall(r'([\d\.]+)', row.xpath('./td//text()')[-2]))>0:
                        self.versions[rect_string] = [ver.strip() for ver in re.findall(r'([\d\.A-Z\sa-z:-]+)', row.xpath('./td//text()')[-2])]
                    else:
                        self.versions[rect_string] = [ver.strip() for ver in re.findall(r'([\d\.A-Z\sa-z:-]+)', row.xpath('./td//text()')[-1])]

                    row.getparent().remove(row)

    def getCVEs(self, label):
        r'''
        + 20-June-2023 
        get the list of CVE's from the Risk Matrix Table along with Components and Versions
        '''
        match = self.root.xpath(f'//*[contains(text(), "{label}")]/following::div/div/table[@class="otable-w2"]')[0]
        match = match.xpath('.//tbody//tr')
        for i in match:
            yield {
                "CVE Id": i.xpath('./th/text()')[0],
                "Component": i.xpath('./td/text()')[0],
                "Versions": i.xpath('./td/text()')[-2]
            }

    def _getMappedAdvisory(self, cve: str):
        r'''
        get Oracle Advisory Link Mapped to CVE
        params:
            cve: str
        '''
        cve_map_adv_url = "https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.html"
        cve_map_adv_url_archv = "https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping-pre-2010.html"
        url = cve_map_adv_url
        if cve.split('-')[2] < 1996:
            url = cve_map_adv_url_archv
        contents = _core.CVENetTools.get(url)
        root = _core.lhtml.fromstring(contents)
        rows = root.xpath('//table[@summary="CVEMapping"]/tbody/tr')

    @property
    def title(self):
        r'''
        returns title from advisory page
        '''
        return self.root.xpath('//div[@class="cc02w1 cwidth"]/h2[1]/text()')

class oracleCVRF():
    r'''
    oracle contains CVRF from oracle advisories
    old cvrf's upto 2012:
        https://www.oracle.com/docs/tech/security-alerts/1932662.xml (RSS)
    CSAF Limited Data
        https://www.oracle.com/docs/tech/security-alerts/oracle-cpu-csaf-rss.xml (CSAF)
    Oracle Security Alerts Page
        https://www.oracle.com/security-alerts/
    '''
    _BASE_URL = "https://www.oracle.com"
    _SEC_ALERT_PAGE = "https://www.oracle.com/security-alerts/"
    _CPU_ARCHIVE_PAGE = "https://www.oracle.com/security-alerts/cpuarchive.html"
    _CVRF_PAGE = ("https://www.oracle.com/docs/tech/security-alerts/%scvrf.xml")
    _CVRF_ARCHIVE_PAGE = "https://www.oracle.com/docs/tech/security-alerts/1932662.xml"
    _CSAF_PAGE = "https://www.oracle.com/docs/tech/security-alerts/oracle-cpu-csaf-rss.xml"
    _CVE_ADV_MAP_PAGE = "https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.html"
    CVE = None

    def __init__(self) -> None:
        raw_content = _core.CVENetTools.get(self._SEC_ALERT_PAGE)
        self.root = _core.lhtml.fromstring(raw_content.encode('utf-8'))

    def _getAdvMap(self, cve:str) -> str:
        raw_content = _core.CVENetTools.get(self._CVE_ADV_MAP_PAGE)
        root = _core.lhtml.fromstring(raw_content.encode('utf-8'))
        return self._BASE_URL+root.xpath(f'//table[@summary="CVEMapping"]/tbody/tr[contains(./td/text(), "{cve}")]//a/@href')[0]

    def _CVE(self, cve, adid, new=None):
        r'''
        only works for older CPU <= 2016
        '''
        _pages = {}
        if new == None:
            cvrf_page = _core.CVENetTools.get(self._CVRF_ARCHIVE_PAGE)
        else:
            cvrf_page = _core.CVENetTools.get((self._CVRF_PAGE) % adid)
        root_cvrf_page = _core.lhtml.fromstring(cvrf_page.encode('utf-8'))
        _ids = root_cvrf_page.xpath('//item')
        for id in _ids:
            key = id.xpath('./guid/text()')[0].lower()
            val = re.findall(r"(http.*xml)", "".join(id.xpath('.//text()')))[0]
            if adid == key:
                print(val)
                _pages[key] = val
            else:
                continue

        _adv_link = _pages[adid]
        _content_ = _core.CVENetTools.get(_adv_link)
        root = _core.lhtml.fromstring(_content_.encode('utf-8'))
        cve_pin = root.xpath(f'//vulnerability[./title/text() = "{cve}"]')
        _pids = list()
        for _pid in cve_pin:
            _pids.extend(_pid.xpath('./productstatuses/status[@type="Known Affected"]/productid/text()'))

        _pids = list(set(_pids))
        affected_family = list()
        self.affected_version = {}
        for _pid_ in _pids:
            affected_family.extend(root.xpath(f'//producttree//branch[@type="Product Family" and .//fullproductname[@productid="{_pid_}"]]/@name'))

        for _family_ in affected_family:
            version = [root.xpath(f'//producttree//branch[@type="Product Family" and @name="{_family_}"]//branch[.//fullproductname[@productid="{_pid_}"] and @type="Product Version"]/@name')[0] for _pid_ in _pids]
            if len(version) > 0:
                self.affected_version[_family_] = sorted(version)

        self.affected_family = set(affected_family)

    @property
    def getCPU(self):
        r'''
        get the mapped advisory ID on passed CVE
        
        returns the latest CPU if cve is not Passed
        '''
        if self.CVE == None:
            return self._BASE_URL+self.root.xpath('//table[./thead//th[contains(text(), "Critical Patch Update")]]/tbody//a/@href')[0]
        elif self.CVE.startswith("CVE"):
            return self._getAdvMap(self.CVE)
        else:
            print("Invalid CVE Id")

    def parseCVRF(self, cvrf_id:str, table=None):
        self.products = {}
        url = (self._CVRF_PAGE % cvrf_id)
        raw_content = _core.CVENetTools.get(url)
        root = _core.lhtml.fromstring(raw_content.encode('utf-8'))
        families = root.xpath('//branch[@type="Product Family"]/@name')
        for family in families:
            self.products[family] = {}
            for prod in root.xpath(f'//branch[@type="Product Family" and @name="{family}"]/branch[@type="Product Name"]/@name'):
                self.products[family][prod] = [prod.xpath('.//branch[@type="Product Version"]/@name') for prod in root.xpath(f'//branch[@type="Product Family" and @name="{family}"]/branch[@type="Product Name" and @name="{prod}"]')][0]

