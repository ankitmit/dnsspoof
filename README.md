The application dnsspoofinject is an on-path DNS packet injector that capture the traffic from a network interface in promiscuous mode, and attempt to inject forged responses to selected DNS A requests.

Command Line format : 

dnsspoofinject [-i interface] [-f hostnames] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    dnsinject selects a default interface to listen on. The same
    interface is used for packet injection.

-f  Read a list of IP address and hostname pairs specifying the hostnames to
    be hijacked. If '-f' is not specified, dnsinject forges replies for
    all observed requests with the local machine's IP address as an answer.
    
<expression> is a BPF filter that specifies a subset of the traffic to be
monitored. This option is useful for targeting a single or a set of particular
victims.

The <hostnames> file contains one IP and hostname pair per line, separated by whitespace.

For example:
10.6.6.6      www.google.com
192.168.1.1   www.facebook.com
192.168.66.6  www.twitter.com

The challenge in implementing this is to make the code optimized enough so that the packet with the Spoofed DNS reply should reach the client before the genuine response packet. 

It is really tough to beat response for some of the highly frequented websites such as google.com and facebook.com for which the most of the servers cache the response and actual DNS resolution does not take  place.
