import os
from os.path import abspath, dirname, join
from setuptools import setup, find_packages

"""
New release procedure

- tox

- edit pierky/ripeatlasmonitor/version.py

- edit CHANGES.rst

- verify RST syntax is ok
    python setup.py --long-description | rst2html.py --strict

- build and verify docs
    cd docs ; make html ; python3 -m http.server ; cd ..

- new files to be added to MANIFEST.in?

- python setup.py sdist

- twine upload dist/*

- git push

- edit new release on GitHub
"""

__version__ = None

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Get proper long description for package
current_dir = dirname(abspath(__file__))
description = open(join(current_dir, "README.rst")).read()
changes = open(join(current_dir, "CHANGES.rst")).read()
long_description = '\n\n'.join([description, changes])
exec(open(join(current_dir, "pierky/ripeatlasmonitor/version.py")).read())

# Get the long description from README.md
setup(
    name="ripe-atlas-monitor",
    version=__version__,

    packages=["pierky", "pierky.ripeatlasmonitor"],
    namespace_packages=["pierky"],
    include_package_data=True,

    license="GPLv3",
    description="A tool to monitor results collected by RIPE Atlas probes and verify they match against predefined expected values.",
    long_description=long_description,
    url="https://github.com/pierky/ripe-atlas-monitor",
    download_url="https://github.com/pierky/ripe-atlas-monitor",

    author="Pier Carlo Chiodi",
    author_email="pierky@pierky.com",
    maintainer="Pier Carlo Chiodi",
    maintainer_email="pierky@pierky.com",

    install_requires=[
        "argcomplete>=1.0.0",
        "IPy>=0.83",
        "python-dateutil>=1.0, != 2.0",
        "ripe.atlas.cousteau>=1.0.7",
        "ripe.atlas.sagan>=1.1.8",
        "ipdetailscache>=0.4.7",
        "pyyaml",
        "pytz",
        "six>=1.10.0"
    ],
    tests_require=[
        "nose",
        "coverage",
        "mock",
    ],
    test_suite="nose.collector",

    scripts=["scripts/ripe-atlas-monitor"],

    keywords=['RIPE', 'RIPE NCC', 'RIPE Atlas', 'Command Line'],

    classifiers=[
        "Development Status :: 4 - Beta",

        "Environment :: Console",

        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",

        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",

        "Operating System :: POSIX",
        "Operating System :: Unix",

        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",

        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
