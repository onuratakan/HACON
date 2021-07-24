from setuptools import setup

import os
from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(name='HACON',
version='pre-alpha',
description="""Lots of cyber security tool""",
url='https://githpipub.com/onuratakan/HACON',
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