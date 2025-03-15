A final project in Magshimim cyber course 2019.

This project defends against DNS poisoning by sniffing on the computer and comparing ips given by the default DNS server with other DNS servers to make sure the ip 
is good, and the default DNS server isn't posioned.

How it does it: by sniffing on the computer looking for DNS requests, extracting the domain and sending it to other DNS servers, getting their results with the ip given *

Why it works: The hacker will have to poison a couple of servers simultaneously, making it much harder, especially if we could work with other DNS servers  *


If you would like to run it, please use Linux and give authorization by typing: sudo python 
authorization is needed because we are sniffing on the computer packets 