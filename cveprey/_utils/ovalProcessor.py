from .. import _core

class ovalProcessor(object):
    def __init__(self, filename: str):
        self._file_object = _core.lhtml.fromstring(filename.encode('utf-8'))

    class _Inventory(object):
        def __init__(self):
            self._inventory = self._file_object.xpath('//definition[@class="inventory"]')

        @property
        def criteria(self):
            pass

    class _Vulnerability(object):
        def __init__(self) -> None:
            self._inventory = self._file_object.xpath('//definition[@class="vulnerability"]')

    class _Tests(object):
        pass

    class _Objects(object):
        pass

    class _States(object):
        pass

    class _Variables(object):
        pass