# Cert Utils

Collection of random SSL-related utilities written in PHP.

The ```cu``` script in the top-level directory is the common entry point for all the commands, and when invoked without arguments will list all the available commands and global options.

## cu build-chain

```
cu build-chain path
```

Build an intermediate certificate chain for an SSL certificate stored in ```path``` and print it on stdout.

The utility assumes that trusted root certificates are located in ```/etc/ssl/certs/```.

## cu find:expired

```
cu find:expired [--expiry] directory
```

Recursively scan ```directory``` for certificate files and report ones that have expired. 

Certificate files are defined as files with .crt or .pem extension.

By default the expiration time is checked against current time, this can be overridden with the optional ```--expiry``` argument which takes string understood by [strtotime() PHP function](http://php.net/strtotime), for example:

``` cu find:expired --expiry="+4 weeks" /ssl-certs/```

will report certificate files that are due to expire in the next 4 weeks.


## cu find:no-chain

```
cu find:no-chain directory
```

Recursively scan ```directory``` for certificate files and report ones that likely contain no certificate chain. Currently it doesn't verify validity of the chain for the certificate files that do contain it.

Certificate files are defined as files with .crt or .pem extension, and are expected to contain the certificate itself along with its chain.


