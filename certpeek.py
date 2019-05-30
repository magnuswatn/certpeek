import sys
import base64
import socket
import string
import urllib.parse

from datetime import datetime

import click

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

__version__ = "2019.05.30"

BAD_BUYPASS_CERTS = [
    "8acd454c36e2f873c90ae6c00df75928daa414a43be745e866e8172344178824",
    "ebdbb3944b2c0c58a1ae4ac058231cda849aa7bec97a9e27ad5d515b47a59cd2",
]

KNOWN_LOGS = {
    "Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=": "Google 'Argon2019' log",
    "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=": "Google 'Argon2020' log",
    "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=": "Google 'Argon2021' log",
    "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=": "Google 'Xenon2019' log",
    "B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw=": "Google 'Xenon2020' log",
    "fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=": "Google 'Xenon2021' log",
    "RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=": "Google 'Xenon2022' log",
    "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=": "Google 'Aviator' log",
    "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=": "Google 'Icarus' log",
    "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=": "Google 'Pilot' log",
    "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=": "Google 'Rocketeer' log",
    "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=": "Google 'Skydiver' log",
    "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFY=": "Cloudflare 'Nimbus2019' Log",
    "Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=": "Cloudflare 'Nimbus2020' Log",
    "RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=": "Cloudflare 'Nimbus2021' Log",
    "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=": "DigiCert Log Server",
    "h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=": "DigiCert Log Server 2",
    "4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4=": "DigiCert Yeti2019 Log",
    "8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=": "DigiCert Yeti2020 Log",
    "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=": "DigiCert Yeti2021 Log",
    "IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=": "DigiCert Yeti2022 Log",
    "/kRhCLHQGreKYsz+q2qysrq/86va2ApNizDfLQAIgww=": "DigiCert Nessie2019 Log",
    "xlKg7EjOs/yrFwmSxDqHQTMJ6ABlomJSQBujNioXxWU=": "DigiCert Nessie2020 Log",
    "7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=": "DigiCert Nessie2021 Log",
    "UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=": "DigiCert Nessie2022 Log",
    "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=": "Symantec log",
    "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=": "Symantec 'Vega' log",
    "FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=": "Symantec 'Sirius' log",
    "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=": "Certly.IO log",
    "dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM=": "Izenpe log",
    "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=": "WoSign log",
    "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=": "Venafi log",
    "AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=": "Venafi Gen2 CT log",
    "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=": "CNNIC CT log",
    "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=": "StartCom log",
    "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=": "Sectigo 'Sabre' CT log",
    "b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=": "Sectigo 'Mammoth' CT log",
}

KNOWN_CERT_TYPES = {
    "2.23.140.1.1": "Extended validation TLS certificate",
    "2.23.140.1.2.1": "Domain validated TLS certificate",
    "2.23.140.1.2.2": "Organization validated TLS certificate",
}


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
@click.argument("host")
@click.option("--proxy", envvar="https_proxy", help="Proxy to use.")
@click.option("--servername", help="Custom SNI name to send in handshake.")
@click.option("--print-pem", is_flag=True, help="Print certs in PEM format.")
def main(host, proxy, servername, print_pem):
    """Peeks at certificates exposed by other hosts."""
    host_split = host.split(":")
    if len(host_split) == 1:
        host = host_split[0], 443
    elif len(host_split) == 2:
        try:
            port = int(host_split[1])
        except ValueError:
            raise click.BadParameter("Port must be integer: {}".format(host_split[1]))
        host = host_split[0], port
    else:
        raise click.BadParameter("Invalid host specified")

    if proxy:
        s = get_socket_via_proxy(proxy, host)
    else:
        s = get_direct_socket(host)

    ctx = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(ctx, s)

    if servername:
        conn.set_tlsext_host_name(servername.encode())
    else:
        conn.set_tlsext_host_name(host[0].encode())

    conn.set_connect_state()
    try:
        conn.do_handshake()
        conn.shutdown()
        conn.close()
    except SSL.Error as error:
        # If the host requires a client certificate
        # the handshake will fail, but we will still
        # get our certificate.
        ssl_error = error

    certs = conn.get_peer_cert_chain()
    if not certs:
        click.secho(
            "Could not retrieve a certificate chain from the specified host: {}".format(
                ":".join(ssl_error.args[0][0])
            ),
            fg="red",
            err=True,
        )
        sys.exit(-1)

    for cert in certs:
        print_cert_info(cert.to_cryptography())
        if print_pem:
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            click.echo(pem_cert.decode())


def get_socket_via_proxy(proxy, host):

    proxy_addr = urllib.parse.urlparse(proxy)
    if proxy_addr.scheme != "http":
        raise click.BadParameter("Only http proxies are supported")

    proxy_split = proxy_addr.netloc.split(":")
    if len(proxy_split) == 1:
        proxy_host = proxy_split[0]
        proxy_port = 8080
    elif len(proxy_split) == 2:
        try:
            port = int(proxy_split[1])
        except ValueError:
            raise click.BadParameter(
                "Proxy port must be integer: {}".format(proxy_split[1])
            )

        proxy_host = proxy_split[0]
        proxy_port = port
    else:
        raise click.BadParameter("Invalid proxy specified")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((proxy_host, proxy_port))
    except socket.error as error:
        click.secho(
            "Unable to connect to {}: {}".format(proxy, error), fg="red", err=True
        )
        sys.exit(-1)

    s.send("CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}\r\n\r\n".format(*host).encode())
    proxy_response = s.recv(1024).decode()
    status_code = proxy_response.split("\r\n")[0].split(" ")[1]
    if status_code != "200":
        click.secho("Computer says no:\n{}".format(proxy_response), fg="red", err=True)
        sys.exit(-1)
    return s


def get_direct_socket(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(host)
    except socket.error as error:
        click.secho(
            "Unable to connect to {}:{} {}".format(*host, error), fg="red", err=True
        )
        sys.exit(-1)
    return s


def print_field(header, values):
    if values and any(values):
        click.secho("[{}]".format(header))
        for value in values:
            click.echo("  {}".format(value))


def get_log_names(scts):
    names = []
    for sct in scts:
        names.append(
            KNOWN_LOGS.get(base64.b64encode(sct.log_id).decode(), "Unknown log")
        )
    return names


def get_key_info(key):
    if isinstance(key, RSAPublicKey):
        return "RSA ({})".format(key.key_size)
    if isinstance(key, EllipticCurvePublicKey):
        return "ECC ({})".format(key.key_size)
    return "Unknown"


def get_type(policies):
    for policy in policies:
        try:
            return KNOWN_CERT_TYPES[policy.policy_identifier.dotted_string]
        except KeyError:
            pass


def print_not_after_status(not_after):
    delta = (not_after - datetime.utcnow()).total_seconds()
    if delta < 0:
        text = click.style("Expired!", fg="red")
    elif delta < 2629743:
        # less than a month
        text = click.style("Expires soon!", fg="yellow")
    else:
        text = click.style("Valid", fg="green")

    return "{} ({})".format(not_after, text)


def print_cert_info(cert):
    sans = []
    scts = []
    policies = []
    for ext in cert.extensions:
        if ext.oid.dotted_string == "2.5.29.17":
            for name in ext.value:
                sans.append(str(name.value))
        elif ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.2":
            scts = [sct for sct in ext.value]
        elif ext.oid.dotted_string == "2.5.29.32":
            policies = ext.value

    click.secho("#############################################################")

    print_field("Subject", [cert.subject.rfc4514_string()])
    print_field("Issuer", [cert.issuer.rfc4514_string()])
    print_field("Serial", [cert.serial_number])
    print_field("Key type", [get_key_info(cert.public_key())])
    print_field("Not before", [cert.not_valid_before])
    print_field("Not after", [print_not_after_status(cert.not_valid_after)])
    print_field("SANs", sans)
    print_field("SCTs", get_log_names(scts))
    print_field("Type", [get_type(policies)])
    print_field("Signature alg", [cert.signature_hash_algorithm.name])
    print_field("SHA1", [cert.fingerprint(hashes.SHA1()).hex()])
    print_field("SHA256", [cert.fingerprint(hashes.SHA256()).hex()])

    if cert.fingerprint(hashes.SHA256()).hex() in BAD_BUYPASS_CERTS:
        click.secho("This is an bad Buypass cert!", fg="red")

    click.echo()


if __name__ == "__main__":
    main()
