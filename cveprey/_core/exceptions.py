'''
This Module Handles all the Exception Occured During Process
'''

class customError(Exception):
    pass


class NET_Exceptions():


    class NVDEmptyError(customError):
        def __init__(self, message:str="Not Found in NVD"):
            super().__init__(f"{message}")


    class _200_(customError):
        def __init__(self, message:str=" "):
            super().__init__(f"{message}")


    class CVEFormatError(customError):
        def __init__(self):
            print("CVE ID is not a valid")


class DumbleExceptions():
    pass