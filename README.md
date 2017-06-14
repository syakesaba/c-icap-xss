c-icap-xss
==========
My first C++ software.  
c-icap is the best ICAP([RFC3507](http://www.measurement-factory.com/std/icap/)) server.  
XSS is a Cross-Site-Scripting. one of the most famous attacking vector on Web applications.

Depends
==========
- c-icap (>=0.3.1) - [http://c-icap.sourceforge.net/](http://c-icap.sourceforge.net/)
- RE2 - [http://code.google.com/p/re2/](http://code.google.com/p/re2/)
- uriparser - [http://uriparser.sourceforge.net/](http://uriparser.sourceforge.net/)

Usage
==========
```sh
apt-get install git gcc build-essential libicapapi-dev libre2-dev liburiparser-dev
git clone https://github.com/syakesaba/c-icap-xss.git
cd c-icap-xss
make all
ln -s libc-icap-xss.so /usr/local/c-icap/lib/c_icap/srv_xss.so
### c-icap.conf
# ...
# ServicesDir /usr/local/c-icap/lib/c_icap
# Service xss srv_xss.so
# ...
### squid.conf
# ...
# icap_service xss_req reqmod_precache bypass=0 icap://localhost:1344/xss
# icap_service xss_resp respmod_precache bypass=0 icap://localhost:1344/xss
# ...
###
```

Author
==========
SYA-KE
