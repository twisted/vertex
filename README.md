[![Build Status](https://travis-ci.org/twisted/vertex.png?branch=master)](https://travis-ci.org/twisted/vertex)
[![codecov.io](https://codecov.io/github/twisted/vertex/coverage.svg?branch=master)](https://codecov.io/github/twisted/vertex?branch=master)
# Divmod Vertex #

Pull up a chair, and let me tell you a story of the once and future Internet.

## The Age of Innocence ##

In the beginning of the Internet, all networking was “peer to peer”.
If you were lucky enough to have an Internet-connected computer, you could talk to any other Internet-connected computer; in fact, being able to do so  was practically the definition of “Internet connected”.

However, many of these computers were the size of a large truck and required a full time staff to operate.
In the fullness of time, the Internet would grow to include much smaller devices, computers owned by individuals.

## The Sundering ##

The growing number of connected devices created a number of problems.
All these new devices needed IP addresses; at first, this was simply a logistical problem that you'd want to avoid, since you might want to connect multiple computers to your home network, and later, there weren't enough IP addresses to go around any more.
So some clever folks came up with Network Address Translation.
As far as the Internet was concerned, your whole network was a single device, with one address; internally, of course, each computer would have its own network address, but a device on the border of the network would hide all that.
This meant that you could connect as many devices to your network as you liked, and you didn't have to ask permission, and nobody outside could even necessarily tell that you'd done so.
NAT was therefore a great innovation - it allowed billions more devices to get connected to the internet.

But NAT also effectively means that as a “consumer” of Internet services, you can make outgoing requests but can not accept incoming ones.
In other words, you can subscribe but you can't publish; you can listen but you can't speak.
Slowly, this began to break things:
Internet telephones that expected to be able to call each other.
Games that expected to be able to make a direct connection between two players.
Even things as simple as file transfer programs that allowed you to send information directly to another person.
All of this can be worked around, of course, but there are few standards for how NAT devices behave, inconsistently implemented.
Most require users to become experts at networking, or endure poor performance, security problems.
Even basic tasks like [updating a video game](https://us.battle.net/support/en/article/firewall-proxy-router-and-port-configuration) require memorization of long lists of numbers and familiarity with network administration.

Nevertheless, even as all of this is happening, as all of this functionality is disappearing, the Internet's popularity is exploding.
What it *does* enable is so amazing that we all forget the even *more* amazing promise we've lost.

The Internet is Broken: Long Live the Internet.

## The Desert Of The Now ##

Today, almost all basic Internet-connected functionailty takes the form of a server - almost always a web site - controlled by a third party, rather than a program you can control on your own computer.
There's nothing wrong with web sites, of course; the web has been a fantastic innovation in its own right.
But there *is* something wrong with *needing* to put your information under someone else's control just because that's the only way to get it from Point A to Point B, where Point A is your house and Point B is your friend's house.

Especially when there are other ways.

Teleconferencing software, video games, and file sharing networks have all *had* to solve this problem in order for their basic functionality to work.
So it's possible to do.
But they've all solved these problems in vastly different, application-specific ways, and none of them share any common infrastructure. for direct communication.
If you want to create a new application that makes use of direct connectivity, you have to become an expert in [about ten times as much technology](https://tools.ietf.org/html/rfc5389) as if you wanted to create a [basic web site](https://www.djangoproject.com/).

## A False Hope ##

IPv6 is coming, of course, and in principle it could free us from all this.

But in practice, it won't.

After two decades of depending on NAT for security, home computers are not prepared for the onslaught of the public Internet.
When IPv6 rolls out to the general public, it will need to be done in such a way that prevents incoming traffic by default.
Without a secure way to allow incoming traffic, networked devices will stay shut off in the way.

# Okay, What Is Vertex, Already?! #

Vertex is a general purpose system for securely connecting to a program running on behalf of another person, with a trust model based on Trust On First Use (TOFU) and Persistence of Pseudonym (POP).

Currently, when a program wants to connect somewhere over the Internet, it gives the name of the machine, and a port number.
Something like:

    example.com 443
    ^ computer  ^ port

With Vertex, instead, a program identifies a *person* and a *purpose*.
Like this:

    bob@b.example.com/messaging
    ^ person          ^ purpose
        ^ server

Let's say Alice has a chat program that she wants to use to talk to Bob.
Alice puts in an identifier like the one above into her that program, and using Vertex, it can talk directly to the same program on Bob's computer; all communication is therefore secured.

## What's the point? ##

If you want to have a program on your computer (or, potentially, your mobile device) communicate some information directly to another, you should be able to do it:

1. easily,
2. securely,
3. quickly, and
4. directly.

Vertex attempts to enable all of this, taking care of the details of networking so that applications can just communicate.

## How's this supposed to work? ##

Alice runs a local Vertex agent, which she registers with a Vertex server on a.example.com as alice@a.example.com; she gets a certificate signed by a.example.com, and then maintains a connection to that server.
Bob registers with a Vertex server on b.example.com as bob@b.example.com; he gets a certificate from b.example.com and maintains a connection to that server.

Alice then connects to b.example.com; since she's never talked to it before, she requests its certificate.
(Alice can also ask a.example.com, or any of her existing connections to other Vertex clients or servers, to double-check on b.example.com's certificate, to make sure that they get the same result, potentially automating the usual call-somebody-up-to-ask-if-the-SSH-server's-key-really-changed workflow we all go through.)

Alice secures her connection to b.example.com with the certificate that a.example.com previously signed; b.example.com verifies it by talking to a.example.com.
On that connection, she asks to speak to Bob.

At this point, b.example.com talks to Bob and sends along Alice's certificate.
If Bob approves of Alice's connection, then (and only then!) b.example.com sends along instructions for how to connect to Bob.

These instructions are a *list* of potential connection techniques; TCPv4, TCPv6, multiple different UDP hole punching techniques, local (behind NAT) addresses, addresses discovered by talking to Vertex servers, and so on.
All of these are attempted, and the best connection is used.
Regardless of which connection is selected, the local Vertex agents on Alice and Bob's computers should use the same TLS certificates to communicate with each other, and the traffic should be encrypted.

## Wow, this sounds great, what kind of shape is it in? ##

Sadly, Vertex's current status is that of "proof of concept".
Many of the things in the story above say "should" instead of "does" because it doesn't actually do those things yet.
It can make some connections over the Internet and transfer some bytes, but:

- It doesn't yet implement a workable trust model, or any way to revoke certificates.
- There's no mechanism to ask your peers to tell you about a certificate to guard aganst DNS cache poisoning on first use.
- Despite all the fancy certificate memory stuff, fundamentally trust is established by plain passwords.
- It stores user passwords in plaintext.
- There's no UI for the local agent, and no real persistence of the "buddy list".
- There's no support for UPnP, or any other kind of automatic router configuration.
- Its UDP-over-TCP implementation doesn't implement [window scaling](https://en.wikipedia.org/wiki/TCP_window_scale_option), among other things; it is *very* slow.
- When using UDP tunnelling, it doesn't currently use encryption at all.  This is actually due to a design flaw, long since fixed, in Twisted's implementation of TLS; Vertex is one of the reasons that [this flaw was fixed](https://twistedmatrix.com/trac/ticket/593).
- There's no defined protocol for an agent to talk to other applications; each agent currently contains all of the code for the applications that want to speak to other nodes.

But all these flaws and all this unfinished work are just a chance for you to be a hero and improve Vertex's functionality until it's actually useful!

### What's "Divmod"? ###

Divmod is a now-defunct start-up company that open sourced many projects in the Twisted ecosystem, including this one.
All the Divmod projects were therefore named “Divmod X”.
As an acknowledgement of Divmod’s contributions, the current maintainers (some of whom worked for Divmod at the time) are preserving that nomenclature.

### Why "Vertex"? ###

The Divmod projects are all named for various mathematical concepts.

The vertex of an angle is where two rays begin or meet, and Vertex is meant to be the meeting point for your network communications.
