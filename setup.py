from setuptools import setup

setup(
    name="Vertex",
    version="0.3.0",
    maintainer="Divmod, Inc.",
    maintainer_email="support@divmod.org",
    url="https://github.com/twisted/vertex",
    packages=["vertex"],
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
)
