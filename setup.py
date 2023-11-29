import os
from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="pysodium",
    version="0.7.16",
    author="Stefan Marsiske",
    author_email="s@ctrlc.hu",
    description="python libsodium wrapper",
    license="BSD",
    keywords="cryptography API NaCl libsodium",
    url="https://github.com/stef/pysodium",
    packages=find_packages(exclude=['test*']),
    long_description=read('README.md'),
    requires=["libsodium"],
    classifiers=["Development Status :: 4 - Beta",
                 "License :: OSI Approved :: BSD License",
                 "Topic :: Security :: Cryptography",
                 "Topic :: Security"],
)
