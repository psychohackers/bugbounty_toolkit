#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bugbounty-toolkit",
    version="2.1.0",
    author="Psycho",
    author_email="psycho@example.com",  # Replace with actual email if desired
    description="Comprehensive Bug Bounty Toolkit for educational purposes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/psycho/bugbounty-toolkit",  # Update with actual URL
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.3",
        "urllib3>=1.26.0",
        "dnspython>=2.1.0",
        "python-nmap>=0.7.0",
        "tqdm>=4.62.0",
        "jinja2>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "bugbounty-toolkit=bugbounty_toolkit:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
