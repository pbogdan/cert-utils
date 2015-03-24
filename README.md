# Cert Utils

Collection of random SSL-related utilities written in PHP.

## build-chain

```
build-chain file
```

Build an intermediate certificate chain for an SSL certificate stored in ```file``` and print it on stdout.

The utility assumes that trusted root certificates are located in ```/etc/ssl/certs/```.

## find-expired

```
find-expired directory
```

Recursively scan ```directory``` for certificate files and report ones that have expired.

Certificate files are defined as files with .crt or .pem extension.

## find-bundles-no-chain

```
find-bundles-no-chain directory
```

Recursively scan ```directory``` for certificate files and report ones that likely contain no certificate chain. Currently it doesn't verify validity of the chain for the certificate files that do contain them.

Certificate files are defined as files with .crt or .pem extension, and are expected to contain the certificate itself along with its chain.


