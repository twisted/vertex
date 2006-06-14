from epsilon import setuphelper

from vertex import version

setuphelper.autosetup(
    name="Vertex",
    version=version.short(),
    maintainer="Divmod, Inc.",
    maintainer_email="support@divmod.org",
    url="http://divmod.org/trac/wiki/DivmodVertex",
    license="MIT",
    platforms=["any"],
    description=
        """
        Divmod Vertex is the first implementation of the Q2Q protocol, which
        is a peer-to-peer communication protocol for establishing
        stream-based communication between named endpoints.
        """,
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Internet"],
    )
