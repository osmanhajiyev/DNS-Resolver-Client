# DNS-Resolver-Client
Given a Domain Name Server this code will find an IP address (or IP addresses) and any other relevant info associated with a given DNS if it exists

Written by: Osman Hajiyev and Peder Shirley with the guidance from Professor Donald Acton


Program will be run at the command line by doing:

java -jar DNSlookup.jar rootDNS name [-6|-t|-t6|].
rootDNS - this is the IP address (in dotted form) of the DNS server you are to start your search at. It may or may not be a root DNS server.
name - this is the fully qualified domain name you are to lookup.
-6 - This option indicates that the IPV6 address for a name is to be retrieved. The default is to retrieve the IPV4 address for a name.
-t - This option specifies that the program is to print a trace of all the queries made and responses received and then the result. (In trace mode if a query is resent because of a timeout the resent query is printed.)
-t6 - This option indicates that a lookup for an IPV6 address is to be performed as well as doing the trace.
