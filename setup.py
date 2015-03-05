from setuptools import setup, find_packages
import re

versionPattern = re.compile(r"""^__version__ = ['"](.*?)['"]$""", re.M)
with open("vertex/_version.py", "rt") as f:
    version = versionPattern.search(f.read()).group(1)

setup(
    name="Vertex",
    version=version,
    maintainer="Twisted Matrix Laboratories",
    maintainer_email="vertex-dev@twistedmatrix.com",
    url="https://github.com/twisted/vertex",
    scripts=["bin/gvertex", "bin/vertex"],
    install_requires=['Twisted>=13.1.0', 'pyOpenSSL>=0.13'],
    license="MIT",
    platforms=["any"],
    description=
        """
        Divmod Vertex is the first implementation of the Q2Q protocol, which
        is a peer-to-peer communication protocol for establishing
        stream-based communication between named endpoints.
        """,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Framework :: Twisted",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Topic :: Communications",
        "Topic :: Internet",
        "Topic :: Internet :: File Transfer Protocol (FTP)",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages() + ['prime.plugins'],
    include_package_data=True,
    )
