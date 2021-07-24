from setuptools import setup

import os
from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()


setup(name='HACON',
version='0.1.1',
description="""Lots of cyber security tool""",
long_description="""
# HACON
Lots of cyber security tool
# Install
```
pip3 install HACON
```
# Usage
```python
from hacon import HACON

HACON.arguments("-h")
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
install_requires=required,
python_requires='>=3.6',
zip_safe=False)