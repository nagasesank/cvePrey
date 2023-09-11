from .. import _core
import re, json


class paloaltoAdvisories(object):
    '''
    Collects the details from paloAlto Advisory

    params:
        cve: str

    properties:
        affected_versions: list
        description: str
        title: str
    '''
    def __init__(self, cve:str):
        self.url = f"https://security.paloaltonetworks.com/json/{cve}"
        self.cve = cve
        self.parsed_object = json.loads(_core.CVENetTools.get(self.url))

    @property
    def affected_vesions(self) -> list:
        return list(map(lambda version: re.findall(r"PAN-OS (.*)", version)[0], self.parsed_object['x_affectedList']))

    @property
    def description(self) -> str:
        return self.parsed_object['description']['description_data'][0]['value']

    @property
    def title(self) -> str:
        return self.parsed_object['CVE_data_meta']['TITLE']

