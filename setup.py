import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "pysodium",
    version = "0.1",
    author = "Stefan Marsiske",
    author_email = "s@ctrlc.hu",
    description = ("yet another libsodium wrapper"),
    license = "BSD",
    keywords = "cryptography API NaCl",
    url = "http://packages.python.org/pysodium",
    #py_modules=['anonshort' ],
    long_description=read('README.md'),
    install_requires = ("cffi"),
    classifiers = ["Development Status :: 4 - Beta",
    #               "License :: OSI Approved :: GNU Affero General Public License v3",
    #               "Environment :: Web Environment",
    #               "Topic :: Internet :: WWW/HTTP",
    #               "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
                   "Topic :: Security",
                   ],
)
