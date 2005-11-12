
from distutils.core import setup

setup(
    name="Vertex",
    version="0.1",
    maintainer="Divmod, Inc.",
    maintainer_email="support@divmod.org",
    url="http://divmod.org/trac/wiki/DivmodVertex",
    license="MIT",
    platforms=["any"],
    description="A Q2Q protocol implementation",
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Internet"],

    packages=['vertex',
              'vertex.scripts',
              'vertex.test'],

    scripts=['bin/vertex', 'bin/certcreate'])
