import setuptools
from rtfsig import VERSION_STRING

with open("README.md", "r") as fh:
    long_description = fh.read()

docs_require = []
tests_require = ["pylint", "pytest", "pytest-cov", "plyara"]
dev_require = ["black", "tox"]

setuptools.setup(
    name="rtfsig",
    version=VERSION_STRING,
    author="David Cannings",
    author_email="david@edeca.net",
    description="Extract potentially unique strings from RTF files for threat hunting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PwCUK-CTO/rtfsig",
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["rtfsig=rtfsig.app:main"],},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Topic :: Security",
    ],
    install_requires=["Jinja2==2.11.2",],
    extras_require={
        "docs": docs_require,
        "tests": tests_require,
        "dev": dev_require + docs_require + tests_require,
    },
)
