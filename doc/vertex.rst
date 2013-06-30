========
 Vertex
========

Files
-----

Interesting files
=================

 conncache.py
   Connection cache for message-based protocols.
 endpoint.py
   Q2Q endpoint should be written here using IStreamClientEndpoint
 ivertex.py
   Interfaces.
 q2q.py
   The main event. Contains AMP verbs for Q2Q protocol,
   connection-attempt code, Q2Q protocol, Q2Q service, and certificate
   store.
 q2qclient.py
   Command-line clients; file sender/receiver, port forwarder.
 q2qstandalone.py
   Presence server frontend components.
 subproducer.py
   Multiplexer of multiple producers.

Less interesting files
======================

 bits.py
   bit array for Sigma
 depserv.py
   MultiService derivative. Possibly junk.
 gtk2hack.py
   What it says.
 ptcp.py
   PTCP, a TCP-alike over UDP. Here be dragons.
 q2qadmin.py
   mantissa shim.
 sigma.py
   cheap knockoff of bittorrent.
 statemachine.py
   used in tcpdfa
 tcpdfa.py
   used in ptcp

Q2Q
---

Protocol
========

AMP messages handled:

- Identity

 * Identify

   Vertex nodes send this to presence servers authoritative for an
   address. The server responds with a self-signed certificate for the
   address. This message will be sent in the clear.

  + q2q address
  + *response*: certificate for address

 * Secure

   Q2Q clients send this to presence servers authoritative for the
   destination address. Upon successful mutual validation of SSL
   certificates, a TLS session using these certificates is
   established. This message will be sent in the clear.

  + local certificate
  + certificate authorities
  + source q2q address (optional)
  + destination q2q address
  + whether the server should verify the client's certificate.

 * Sign

   Q2Q clients send this to presence servers authoritative for their
   own address. The server checks the password and the address given
   in the certificate request, and if valid creates a new certificate
   by signing the certificate request.

  + certificate request
  + password
  + *response*: certificate

- Presence

 * Listen

   Q2Q clients send this to presence servers authoritative for their
   own address. The server registers the client's interest in
   connections for the named services.

  + listening q2q address
  + list of service names
  + description
  + *response*: empty

 * Inbound

   Q2Q clients send this to presence servers authoritative for the
   destination address. Presence servers send this to all Q2Q clients
   with the destination address who have registered interest in
   connections for the named service.

  + service name
  + source q2q address
  + destination q2q address
  + optional udp source port
  + *response*: list of (q2q identity, cert, connection methods, expiration, description)

 * Choke

   Used by VirtualTransport to signal backpressure.

  + connection id

 * Unchoke

   Used by VirtualTransport to signal relief of backpressure.

  + connection id

- Virtual

  Q2Q clients send this to presence servers after receiving a response
  to Inbound. Presence servers send this to destination Q2Q clients
  after receiving a Virtual message. Starts a VirtualTransport upon
  receipt.

 + connection id
 + *response*: empty

- WRITE

  Low-level AMP command sent over a virtual channel. For passing to a
  Q2Q client, through a presence server.

 + data
 + *response*: empty

- BindUDP

  Q2Q clients send this to presence servers after receiving a response
  to Inbound. Presence servers send this to destination Q2Q clients
  after receiving a BindUDP message. Used as part of PTCP connection
  process; the receiving Q2Q client sends a UDP packet to the
  requested (host, port) address.

 + protocol name
 + source q2q address
 + destination q2q address
 + udp source (host, port)
 + udp destination (host, port)
 + *response*: empty

- WhoAmI

  Q2Q clients send this to presence servers. The response is the
  (host, port) the server received the message from. Used as part of
  address discovery.

 + *response*: (IP, port) pair

- SourceIP

 All Vertex nodes send this message to their peer upon connection. The
 remote node responds with the IP it received the message from.

 + *response*: probable public IP

- RetrieveConnection

 + connection identifier


Other notes
===========

Presence server
~~~~~~~~~~~~~~~

starts a Q2QService with file-based cert store and a pFF for an admin
that unconditionally adds users when asked to.

Cert storage
~~~~~~~~~~~~

provides IRealm for IQ2QUser, avatars can sign cert requests.
manages private certs for users

Q2Q.requestCertificateForAddress invokes the cert management stuff.

Q2QService
~~~~~~~~~~

protocolFactoryFactory maps address/protocol-name to a handler for connections.

public methods:

 listenQ2Q
   ephemeral publication of interest in connections
 requestCertificateForAddress
   initial "login" for a client to presence server
 startService
   might start ptcp dispatcher, might listen for q2q
   connections, might listen for inbound connections
 sendMessage
   find a cached q2q connection, send an amp message
 connectQ2Q
   creates a connection from a pair of addresses and a protocol
