from setuptools import setup, find_packages
import os

# Read README
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="ixoryn",
    version="1.0.0",
    author="Ixoryn Security Team",
    description="Advanced Security Intelligence Platform — Cryptography, Steganography, URL Audit, Password Audit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ademohmustapha/ixoryn",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0",
        "argon2-cffi>=23.1",
        "PyNaCl>=1.5",
        "bcrypt>=4.0",
        "Pillow>=10.0",
        "pydub>=0.25",
        "numpy>=1.24",
        "scipy>=1.10",
        "opencv-python>=4.8",
        "stegano>=0.11",
        "requests>=2.31",
        "dnspython>=2.4",
        "python-whois>=0.8",
        "tld>=0.13",
        "urllib3>=2.0",
        "certifi>=2023.7",
        "idna>=3.4",
        "beautifulsoup4>=4.12",
        "sslyze>=5.2",
        "hashid>=3.1",
        "passlib>=1.7",
        "zxcvbn>=4.4",
        "colorama>=0.4",
        "rich>=13.0",
        "prompt_toolkit>=3.0",
        "tabulate>=0.9",
        "tqdm>=4.65",
        "pyfiglet>=0.8",
        "chardet>=5.2",
        "python-magic>=0.4",
        "filelock>=3.12",
    ],
    entry_points={
        "console_scripts": [
            "ixoryn=ixoryn:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
    ],
    keywords="security cryptography steganography phishing password hash forensics",
)
