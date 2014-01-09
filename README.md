nginx_md5_filter
================

A content filter for nginx, which returns the md5 hash of the content otherwise returned.

Installation
------------
As with all nginx modules, this must be built into the executable.
Here's a simple example building and installing nginx with this module (I use v1.4.4 only so the example would actually work instead of 1.4.x)
```
wget 'http://nginx.org/download/nginx-1.4.4.tar.gz' #or using the latest version
tar -xzvf nginx-1.4.4.tar.gz
cd nginx-1.4.4

./configure --add-module=/path/to/nginx_md5_filter
make
make install
```

Usage
-----

Currently this module has an extremely simple config file language.
```
location /hash {
    md5_filter on;
    proxy_pass @content;
}
```

Future versions, I plan on implementing a request header flag to enable/disable the filter, removing the need for a hash location.

Output
------
When activated, in place of the content that would be served, the body will be replaced by the 32byte hexdigest of the content (similar to the linux cmd md5sum).
Additionally, a X-Content-Length header will be set to the original Content-Length.
