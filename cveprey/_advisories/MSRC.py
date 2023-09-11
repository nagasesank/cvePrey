from .. import _core
import re, json

'''
https://api.msrc.microsoft.com/sug/v2.0/en-US/releaseNote
https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2023-21796

https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?
    $orderBy=cveNumber desc&
    $filter=(
        releaseDate gt 2022-08-10T00:00:00+05:30 or latestRevisionDate gt 2022-08-10T00:00:00+05:30
        ) 
        and 
        (
            releaseDate lt 2023-02-11T23:59:59+05:30 or latestRevisionDate lt 2023-02-11T23:59:59+05:30
        )
'''

class MSRC(object):

    class Vulnerability(object):
        def __init__(self, cve:str):
            self.cve = cve
            self.url = f"https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{cve}"
            self.parsed = json.loads(_core.CVENetTools.get(self.url))

        @property
        def title(self):
            return self.parsed['cveTitle']

        @property
        def releaseDate(self):
            return self.parsed['releaseDate']

        def __repr__(self) -> str:
            return f"<object MSRC.Vulnerability>"

    def releaseNotes(object):
        pass

    def SUG(object):
        pass

