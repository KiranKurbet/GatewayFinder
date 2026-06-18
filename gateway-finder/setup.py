from setuptools import setup, find_packages
from pathlib import Path

long_desc = Path("README.md").read_text(encoding="utf-8")

setup(
    name             = "gateway-finder",
    version          = "2.0.0",
    author           = "KiranKurbet",
    description      = "Professional network gateway discovery and security assessment CLI",
    long_description = long_desc,
    long_description_content_type = "text/markdown",
    url              = "https://github.com/KiranKurbet/GatewayFinder",
    packages         = find_packages(exclude=["tests*"]),
    python_requires  = ">=3.8",
    install_requires = [
        "click>=8.0",
        "rich>=13.0",
        "scapy>=2.5",
        "netifaces>=0.11",
    ],
    extras_require = {
        "full": [
            "requests>=2.28",
            "python-nmap>=0.7",
        ],
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
        ],
    },
    entry_points = {
        "console_scripts": [
            "gf = gateway_finder.cli:main",
        ],
    },
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    keywords = [
        "gateway", "network", "security", "penetration-testing",
        "arp", "fingerprinting", "red-team", "recon",
    ],
)
