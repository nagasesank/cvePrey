# CVE Prey
_A CVE Automation Framework, Written in Python3 !_

# Legal Notice
This repository is _not_ associated with or endorsed by providers of the APIs contained in this GitHub repository. This project is intended **for educational purposes only**. This is just a little personal project. Sites may contact me to improve their security or request the removal of their site from this repository.

Please note the following:

1. **Disclaimer**: The APIs, services, and trademarks mentioned in this repository belong to their respective owners. This project is _not_ claiming any right over them nor is it affiliated with or endorsed by any of the providers mentioned.

2. **Responsibility**: The author of this repository is _not_ responsible for any consequences, damages, or losses arising from the use or misuse of this repository or the content provided by the third-party APIs. Users are solely responsible for their actions and any repercussions that may follow.

3. **Educational Purposes Only**: This repository and its content are provided strictly for educational purposes. By using the information and code provided, users acknowledge that they are using the APIs and models at their own risk and agree to comply with any applicable laws and regulations.

4. **Copyright**: All content in this repository, including but not limited to code, images, and documentation, is the intellectual property of the repository author, unless otherwise stated. Unauthorized copying, distribution, or use of any content in this repository is strictly prohibited without the express written consent of the repository author.

5. **Updates and Changes**: The author reserves the right to modify, update, or remove any content, information, or features in this repository at any time without prior notice. Users are responsible for regularly reviewing the content and any changes made to this repository.

By using this repository or any code related to it, you agree to these terms. The author is not responsible for any copies, forks, or reuploads made by other users. This is the author's only account and repository. To prevent impersonation or irresponsible actions, you may comply with the MIT license this Repository uses.

<br>

# Usage:
### Installation
```bash
$ git clone https://github.com/iam048/cvePrey.git
$ cd cvePrey/
$ python3 setup.py install --user
```

### Working with Package
```python3
>>> import cveprey
>>> cve_info = cveprey.CVE("CVE-2021-1337")
>>> cve_info.get_nvd_data()
>>> cve_info.nvd_data.description
'Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV016, RV042, RV042G, RV082, RV320, and RV325 Routers could allow an authenticated, ..[SNIP].. affected device.'
```