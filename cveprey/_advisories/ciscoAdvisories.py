from .. import _core
import re, json
from .. _utils.dec import *

FAMILIES = {
    'CVRFPID-93036': 'Cisco IOS XE Software',
    'CVRFPID-5834': 'Cisco IOS XR Software',
    'CVRFPID-279755': 'Cisco UTD SNORT IPS Engine Software',
    'CVRFPID-220203': 'Cisco Firepower Threat Defense Software'
}

def _filter(item: list) -> str:
    return sorted(list(set(filter(None, item))))

class ciscoAdvisories():
    r'''
    Extract details from Cisco Advisories
    params:
        cve: str
        url: str

    methods:
        cvrf_contents

    properties:
        published
        last_modified_on
        title
        ad_id
        cvrf_link
        csaf_link
        affected_cve_list
        affected_bug_id_list
        affected_cwe
    '''
    def __repr__(self) -> str:
        return "<class ciscoAdvisories *Cisco Family **cvePrey>"

    def __init__(self, cve: str, url: str):
        self.cve = cve
        self.raw_content = _core.CVENetTools.get(url)
        self.root = _core.lhtml.fromstring(self.raw_content)

    @property
    def published_on(self):
        return "".join(self.root.xpath('//div[@id="ud-published"]/div[@class="divLabelContent"]/text()'))

    @property
    def last_modified_on(self):
        return "".join(self.root.xpath('//div[@id="ud-last-updated"]/div[@class="divLabelContent"]/text()'))

    @property
    def title(self) -> str:
        return self.root.xpath('//h1[@class="headline"]/text()')[0]

    @property
    def ad_id(self):
        return self.root.xpath('//div[@id="divpubidvalue"]/text()')

    @property
    def cvrf_link(self) -> str:
        return self.root.xpath('//a[contains(text(), "Download CVRF")]/@href')[0]

    @property
    def csaf_link(self) -> str:
        return self.root.xpath('//a[contains(text(), "Download CSAF")]/@href')[0]

    @property
    def affected_cve_list(self):
        if self.root.xpath('//span[@id="fullcvecontent_content"]'):
            val = re.findall(r'(CVE-\d+-\d+)',
                            self.root.xpath('//div[@class="cve-cwe-containerlarge"]//div[@class="CVEList"]/span[@id="fullcvecontent_content"]/text()')[0])
        else:
            val = re.findall(r'(CVE-\d+-\d+)',
                            "".join(self.root.xpath('//div[@class="cve-cwe-containerlarge"]//div[@class="CVEList"]/div/text()')))
        return list(set(val))

    @property
    def affected_bug_id_list(self):
        if self.root.xpath('//span[@id="fullddtscontent_content"]'):
            val = self.root.xpath('//div[@class="ddtsList"]/span[@id="fullddtscontent_content"]/a/text()')
        else:
            val = self.root.xpath('//div[@class="ddtsList"]/div/a/text()')
        return list(set(val))

    @property
    def affected_cwe(self):
        return self.root.xpath('//div[@class="CWEList"]/div/text()')

    @property
    def vulnerable_products(self):
        return _filter("".join(self.root.xpath('//div[@id="vulnerableproducts"]/ul//text()')).split('\n'))

    @property
    def not_vulnerable_products(self):
        return _filter("".join(self.root.xpath('//div[@id="productsconfirmednotvulnerable"]/ul//text()')).split('\n'))

    def cvrf_contents(self):
        return self.CVRF(self.cvrf_link, self.cve)

    class CVRF():
        r'''
        Collects the Affected Versions from the CVRF
        params:
            cvrf: str
            cve: str

        properties:
            pids
            affected_versions
            affected_products
            export

        methods:
            get_pid
        '''
        def __repr__(self) -> str:
            return "<class ciscoAdvisories.CVRF *Cisco Family **cvePrey>"

        def __init__(self, cvrf: str, cve: str):
            self.cve = cve
            self.cvrf_raw = _core.CVENetTools.get(cvrf)
            self.cvrf_parsed_object = _core.lhtml.fromstring(self.cvrf_raw.encode('utf-8'))

        @property
        def pids(self) -> list:
            pids = self.cvrf_parsed_object.xpath(f'//vulnerability[./cve[contains(text(),"{self.cve}")]]/productstatuses/status[@type="Known Affected"]/productid/text()')
            return pids

        def get_pid(self, id: str) -> str:
            return self.cvrf_parsed_object.xpath(f'//fullproductname[@productid="{id}"]/text()')[0]

        @property
        def affected_versions(self) -> dict:
            affected_versions = {}
            all_affected_pids = self.pids
            all_affected_strings = [self.cvrf_parsed_object.xpath(f'//fullproductname[@productid="{i}"]/text()')[0] for i in all_affected_pids]
            
            affected_softwares = self.affected_software
            products = self.affected_products
            for software in affected_softwares:
                affected_versions[software] = {}
                products.pop(products.index(software))

            for affected_software in affected_versions.keys():
                pattern = f'{affected_software}\s(\S+)$'
                try:
                    affected_versions[affected_software]['All'] = [re.findall(pattern, string)[0]
                        for string in all_affected_strings
                        if affected_software in string and len(re.findall(pattern, string))>0]
                    if len(affected_versions[affected_software]['All']) == 0:
                        del affected_versions[affected_software]['All']
                except Exception as err:
                    continue
            
            if ':' in "".join(all_affected_pids):
                for affected_software in affected_versions.keys():
                    for product in products:
                        try:
                            pattern = f'{affected_software}\s(\S+) when'
                            affected_versions[affected_software][product] = [re.findall(pattern, string)[0] \
                            for string in all_affected_strings \
                            if product in string and affected_software in string and len(re.findall(pattern, string))>0]
                            if len(affected_versions[affected_software][product]) == 0:
                                del affected_versions[affected_software][product]
                        except Exception as err:
                            print(err)
                            continue
            
            return affected_versions

        @property
        def affected_products(self) -> list:            
            return _filter(self.cvrf_parsed_object.xpath(f'//branch[@type="Product Name"]/@name'))
        
        @property
        def affected_software(self) -> list:
            return list(set(self.cvrf_parsed_object.xpath('//producttree/branch/branch[@type="Product Name"]/@name')))

        @property
        def export(self):
            with open(f'{self.cve}_cvrf.xml', 'w') as f:
                f.write(self.cvrf_raw)
            f.close()


class ciscoMappingVersions(object):
    r'''
    Get Cisco mapping versions from Cisco Feature Navigation Service and map them to versions
    '''
    class CFN(_core.CVENetTools):
        r'''
        Cisco Feature Navigation Class
        '''
        @property
        def getAllPlatforms(self):
            headers = {"Content-Type": "application/json"}
            url = 'https://cfnngws.cisco.com/getAllPlatforms'
            url_old = 'https://cfnngws.cisco.com/api/old/platform'
            url_response = json.loads(self.get(url))
            for family in ['IOS', 'IOS XE']:
                data = '{"os_type": "'+family+'"}'
                url_response.extend(json.loads(self.post(url_old, headers=headers, data=data)))
            
            for x in url_response:
                try:
                    Platform_id = x['Platform_id']
                    Platform_name = x['Platform_name']
                except Exception:
                    Platform_id = x['platform_id']
                    Platform_name = x['platform_name']

                yield {
                    "Platform_id": Platform_id,
                    "Platform_name": Platform_name,
                }
        
        @property
        def getAllFeatures(self):
            url = 'https://cfnngws.cisco.com/getAllFeatures'
            return json.loads(self.get(url))
        
        @property
        @cache
        def getVersions(self):
            pass


    def mapped_iosxe_ios(self, iosxe_versions: list|str) -> list:
        versions = json.loads(open(os.path.dirname(__file__) + '/../_utils/iosxe-ios.json', 'r').read())
        try:
            if type(iosxe_versions) == list:
                ret = [versions.get(mapped.upper()) for mapped in iosxe_versions]
            else:
                ret = [versions.get(iosxe_versions.upper())]
        except Exception:
            pass
        
        return list(filter(None, ret))

    def mapped_ios_iosxe(self, ios_versions: list|str) -> list:
        versions = json.loads(open(os.path.dirname(__file__) + '/../_utils/iosxe-ios.json', 'r').read())
        try:
            if type(ios_versions) == list:
                ret = [key for key, value in versions.items() 
                        if [value.upper()] == [ios_version.upper() for ios_version in ios_versions]]
            else:
                ret = [key for key, value in versions.items() if value.upper() == ios_versions]
        except Exception:
            pass
        
        return list(filter(None, ret))
    

class ciscoSecurityAdvisories(object):
    r'''
    Collects CVE information from Cisco Security Center
    Collects Latest CVE Updates from Cisco Security Center

    ref_url = https://tools.cisco.com/security/center/publicationService.x?criteria=exact&cves=&keyword=&last_published_date=&limit=20&offset=0&publicationTypeIDs=1,3&securityImpactRatings=&sort=-day_sir&title=
    '''
    class cveData(object):
        def __init__(self, cve: str):
            url = f'https://sec.cloudapps.cisco.com/security/center/publicationService.x?criteria=exact&cves={cve}&publicationTypeIDs=1,3'
            self._data = json.loads(_core.CVENetTools.get(url))

        @property
        def adv_link(self):
            return self._data[0]['url']

    def _cve_analyse(self, cves: dict):
        for cve in cves:
            yield {
                'CVE': cve['cve'],
                'Title': cve['title'],
                'Adv Url': cve['url'],
                'severity': cve['severity'],
                'last updated': cve['lastPublished']
            }
    
    def get_latest_cves_list(self):
        url = 'https://tools.cisco.com/security/center/publicationService.x?criteria=exact'
        data = self._cve_analyse(json.loads(_core.CVENetTools.get(url)))

        return list(data)
   


class versionsData(object):
    r'''
    Collects Latest Release versions from cisco software checker
    
    '''
    def __init__(self):
        self.versions = {}
        _Links = {
            'IOS': 'https://tools.cisco.com/security/center/getIOSVersions',
            'IOSXE': 'https://tools.cisco.com/security/center/getIOSXEVersions',
            'NXOS': 'https://tools.cisco.com/security/center/getNXOSVersionsData',
            'ASA': 'https://tools.cisco.com/security/center/getASAVersionsData',
            'FMC': 'https://tools.cisco.com/security/center/getFMCVersionsData',
            'FXOS': 'https://tools.cisco.com/security/center/getFXOSVersionsData',
            'FTD': 'https://tools.cisco.com/security/center/getFTDVersionsData',
            'AciOSPlatform': 'https://tools.cisco.com/security/center/getAciOSPlatformData' 
        }
        for key in _Links.keys():
            self.versions[key] = json.loads(_core.CVENetTools.get(_Links[key]))


def search(cve: str):
    pass