from .. import _core
import json

'''
Analysis

url = https://gitlab.com/gitlab-org/cves/-/raw/master/2022/CVE-2022-3820.json
'''

class gitLabAdvisories():
    def __init__(self, cve) -> None:
        self.url = "https://gitlab.com/gitlab-org/cves/-/raw/master/{year}/{cve}.json".format(year=cve.split('-')[1], cve=cve)
        self._parsed_object = json.loads(_core.CVENetTools.get(self.url))

    @property
    def title(self) -> str:
        try:
            return self._parsed_object['containers']['cna']['title']
        except Exception as err:
            return ""

    @property
    def description(self) -> str:
        try:
            return self._parsed_object['description']['description_data'][0]['value']
        except KeyError:
            return self._parsed_object['containers']['cna']['descriptions'][0]['value']

    @property
    def adv_link(self) -> str:
        try:
            return [text['url'] for text in self._parsed_object['references']['reference_data'] if text['refsource'] == "CONFIRM"][0]
        except Exception as err:
            return self.url

    @property
    def affected_versions(self) -> list:
        try:
            version_col = self._parsed_object['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data']
            return [text['version_value'] for text in version_col]
        except KeyError:
            version_col = [
                [ver['version'], ver['lessThan']] if ver['lessThan'] 
                    else [ver['version']] 
                    for ver in self._parsed_object['containers']['cna']['affected'][0]['versions']]
            return version_col
    
    @property
    def affected_product(self) -> str:
        try:
            return self._parsed_object['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['product_name']
        except KeyError:
            return self._parsed_object['containers']['cna']['affected'][0]['product']
