#!/usr/bin/env python3
"""
Bug Bounty Toolkit Setup Configuration
Educational Purpose Only - Cybersecurity Project
"""

from setuptools import setup, find_packages
import os
import re

# Read the contents of README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements from requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith('#')]

def get_version():
    """Extract version from the main script"""
    with open("bugbounty_toolkit.py", "r", encoding="utf-8") as f:
        content = f.read()
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            return match.group(1)
    return "2.0.0"

def get_author_info():
    """Extract author information from the main script"""
    with open("bugbounty_toolkit.py", "r", encoding="utf-8") as f:
        content = f.read()
        author_match = re.search(r'__author__\s*=\s*["\']([^"\']+)["\']', content)
        instagram_match = re.search(r'__instagram__\s*=\s*["\']([^"\']+)["\']', content)
        
        author = author_match.group(1) if author_match else "Psycho"
        instagram = instagram_match.group(1) if instagram_match else "@the_psycho_of_hackers"
        
        return author, instagram

author, instagram = get_author_info()

setup(
    name="bugbounty-toolkit",
    version=get_version(),
    author=author,
    author_email="educational-purpose-only@example.com",
    description="Comprehensive Bug Bounty Toolkit for Educational and Authorized Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/psychohackers/bugbounty-toolkit",
    packages=find_packages(),
    py_modules=["bugbounty_toolkit"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Education :: Testing",
        "License :: Free for educational use",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Unix",
        "Operating System :: MacOS",
        "Natural Language :: English",
    ],
    keywords=[
        "bugbounty",
        "cybersecurity",
        "penetration-testing",
        "security",
        "reconnaissance",
        "vulnerability-scanning",
        "educational",
        "ethical-hacking",
        "web-security"
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'bugbounty-toolkit=bugbounty_toolkit:main',
            'bbtoolkit=bugbounty_toolkit:main',
            'psycho-toolkit=bugbounty_toolkit:main',
        ],
    },
    package_data={
        '': [
            'README.md',
            'requirements.txt',
            'LICENSE',
            'wordlists/*.txt',
            'config/*.json',
        ],
    },
    include_package_data=True,
    project_urls={
        "Documentation": "https://github.com/psychohackers/bugbounty-toolkit/wiki",
        "Source": "https://github.com/psychohackers/bugbounty-toolkit",
        "Tracker": "https://github.com/psychohackers/bugbounty-toolkit/issues",
        "Educational Resources": "https://github.com/psychohackers/bugbounty-toolkit/wiki/Educational-Resources",
    },
    license="Educational Use Only - See LICENSE file for details",
    options={
        'bdist_wheel': {
            'universal': True
        }
    },
    # Additional metadata
    platforms=["any"],
    zip_safe=False,
)