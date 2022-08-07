# certpeek


Certpeek peeks at the certificates exposed by SSL/TLS enabled hosts. Perfect for a quick look for debugging.

And, it support tunneling through a HTTP proxy!

<p align="center"><img width="707" alt="Certpeek in action" src="https://github.com/magnuswatn/certpeek/blob/main/certpeek.png?raw=true"></p>

Usage:
```
Usage: certpeek [OPTIONS] HOST

  Peeks at certificates exposed by other hosts.

Options:
  --version          Show the version and exit.
  --proxy TEXT       Proxy to use.
  --servername TEXT  Custom SNI name to send in handshake.
  --no-servername    Do not send SNI in the handshake.
  --print-pem        Print certs in PEM format.
  --first-only       Only process the first retrieved cert.
  --openssl-format   Print cert info like OpenSSL.
  -h, --help         Show this message and exit.
```

Install with pip:

```
pip install certpeek
```

or with pipx:
```
pipx install certpeek
```
