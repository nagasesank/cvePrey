import setuptools, re

version = re.findall(r'release="(.*)"', open('VERSION', 'r').read())[0]

setuptools.setup(
    name="cveprey",
    version=version,
    license='MIT',
    author="iam048",
    url='https://github.com/iam048/cvePrey.git',
    description="Python Package for Scraping CVE Content",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ]
)