from setuptools import setup

from setuptools import setup



setup(name='HACON',
version='0.8.1',
description="""Lots of cyber security tool""",
long_description="""
# HACON
Lots of cyber security tool
# Install
```
pip3 install HACON
```
# Using
## In another script
```python
from hacon import HACON

HACON.arguments("-h")
```
## In command line
```python
HACON -h
```

# With docker
## Install 
```
docker pull ghcr.io/onuratakan/hacon:latest
```
## Using
```
docker run -t -i  --network=host ghcr.io/onuratakan/hacon /bin/sh
```
and type
```python
HACON -h
```

# Reminder
Important Information and Reminder Information and programs in all repositories are created for testing purposes. Any legal responsibility belongs to the person or organization that uses it.

""",
long_description_content_type='text/markdown',
url='https://github.com/onuratakan/HACON',
author='Onur Atakan ULUSOY',
author_email='atadogan06@gmail.com',
license='MIT',
packages=["hacon"],
package_dir={'':'src'},
package_data={
    "hacon": ["wordlists/*.txt"],
},
install_requires=[
    "scapy==2.4.5",
    "scapy-http==1.8.2",
    "prettytable==2.1.0",
    "wcwidth==0.2.5",
    "dnspython==2.1.0",
    "future==0.18.2",
    "python_whois==0.7.3",
    "requests==2.25.1",
    "mac-vendor-lookup==0.1.11"
],
entry_points = {
    'console_scripts': ['HACON=hacon.hacon:HACON.arguments'],
},
python_requires='>=3.6',
zip_safe=False)
