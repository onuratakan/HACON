from setuptools import setup

import os
from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except(IOError, ImportError):
    long_description = open('README.md').read()

setup(name='HACON',
version='0.1.2-alpha',
description="""Lots of cyber security tool""",
long_description=long_description,
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