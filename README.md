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


Run it with uvx:

```
uvx certpeek google.no
```

Or install it permanently with either

uv:

```
uv tool install certpeek
```

pipx:
```
pipx install certpeek
```

or pip:

```
pip install certpeek
```
