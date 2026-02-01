from setuptools import setup, find_packages

setup(
    name="ixoryn",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "argon2-cffi",
        "rich",
        "pillow",
        "soundfile",
        "pydub",
        "passlib",
        "dnspython",
        "idna",
        "tldextract",
        "scikit-learn",
        "numpy"
    ],
    entry_points={
        "console_scripts": [
            "ixoryn=ixoryn:main"
        ]
    },
)

