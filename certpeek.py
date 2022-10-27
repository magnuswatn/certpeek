import socket
import sys
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Iterable, List, Optional, Union
from urllib.parse import urlsplit

import click
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate, GeneralName, Name, PolicyInformation
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp
from OpenSSL import SSL, crypto

__version__ = "2022.10.27"

BAD_BUYPASS_CERTS = [
    "8acd454c36e2f873c90ae6c00df75928daa414a43be745e866e8172344178824",
    "ebdbb3944b2c0c58a1ae4ac058231cda849aa7bec97a9e27ad5d515b47a59cd2",
    "8acd454c36e2f873c90ae6c00df75928daa414a43be745e866e8172344178824",
    "f543633a628e37effc6da952593657bcc5b24b1d590c35b61469027754460dd7",
    "7ac99c1e48e7e935ada22488adac80bfe6e6503cfc54077b9547ff20f3e5ccd5",
    "ff7462796eb657215b6eefa9d821f4beb808e52041cc84dc81b28ca8265bb74f",
    "f66fb7a934e56ecacc65ccb73e6c2be75ec58b8dfe35564b3d6741032af8aaf6",
    "ebdbb3944b2c0c58a1ae4ac058231cda849aa7bec97a9e27ad5d515b47a59cd2",
    "c651aaf5290c2f028246afd39a13008f8c6b83fa658d1107a7eeab7a7a8114ae",
    "0a59b558ae7fce4cba149acfe0609e9d14e301a38421ceabe61347960376a400",
    "a047c5d423d9c0a6c020b624c3bdd4b5689113605e956c3ef0eba4ae5e82363d",
    "d2d1da9c14f62d97465f337d26788c079ee5450a42d3dadb00ad0eb20f18ec49",
]

KNOWN_LOGS = {
    "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=": "CNNIC CT log",
    "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=": "Certly.IO log",
    "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFY=": "Cloudflare 'Nimbus2019' Log",
    "Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=": "Cloudflare 'Nimbus2020' Log",
    "RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=": "Cloudflare 'Nimbus2021' Log",
    "QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=": "Cloudflare 'Nimbus2022' Log",
    "ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=": "Cloudflare 'Nimbus2023' Log",
    "2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=": "Cloudflare 'Nimbus2024' Log",
    "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=": "DigiCert Log Server",
    "h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=": "DigiCert Log Server 2",
    "/kRhCLHQGreKYsz+q2qysrq/86va2ApNizDfLQAIgww=": "DigiCert Nessie2019 Log",
    "xlKg7EjOs/yrFwmSxDqHQTMJ6ABlomJSQBujNioXxWU=": "DigiCert Nessie2020 Log",
    "7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=": "DigiCert Nessie2021 Log",
    "UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=": "DigiCert Nessie2022 Log",
    "s3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZo=": "DigiCert Nessie2023 Log",
    "c9meiRtMlnigIH1HneayxhzQUV5xGSqMa4AQesF3crU=": "DigiCert Nessie2024 Log",
    "5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlA=": "DigiCert Nessie2025 Log",
    "4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4=": "DigiCert Yeti2019 Log",
    "8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=": "DigiCert Yeti2020 Log",
    "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=": "DigiCert Yeti2021 Log",
    "IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=": "DigiCert Yeti2022 Log",
    "BZwB0yDgB4QTlYBJjRF8kDJmr69yULWvO0akPhGEDUo=": "DigiCert Yeti2022-2 Log",
    "Nc8ZG7+xbFe/D61MbULLu7YnICZR6j/hKu+oA8M71kw=": "DigiCert Yeti2023 Log",
    "SLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHM=": "DigiCert Yeti2024 Log",
    "fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebg=": "DigiCert Yeti2025 Log",
    "Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=": "Google 'Argon2019' log",
    "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=": "Google 'Argon2020' log",
    "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=": "Google 'Argon2021' log",
    "KXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4Q=": "Google 'Argon2022' log",
    "6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=": "Google 'Argon2023' log",
    "7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=": "Google 'Argon2024' log",
    "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=": "Google 'Aviator' log",
    "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=": "Google 'Icarus' log",
    "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=": "Google 'Pilot' log",
    "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=": "Google 'Rocketeer' log",
    "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=": "Google 'Skydiver' log",
    "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=": "Google 'Xenon2019' log",
    "B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw=": "Google 'Xenon2020' log",
    "fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=": "Google 'Xenon2021' log",
    "RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=": "Google 'Xenon2022' log",
    "rfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgoo=": "Google 'Xenon2023' log",
    "dv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQ=": "Google 'Xenon2024' log",
    "dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM=": "Izenpe log",
    "lCC8Ho7VjWyIcx+CiyIsDdHaTV5sT5Q9YdtOL1hNosI=": "Let's Encrypt 'Oak2021' log",
    "36Veq2iCTx9sre64X04+WurNohKkal6OOxLAIERcKnM=": "Let's Encrypt 'Oak2022' log",
    "tz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJk=": "Let's Encrypt 'Oak2023' log",
    "O1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61Bc=": "Let's Encrypt 'Oak2024H1' log",
    "PxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4=": "Let's Encrypt 'Oak2024H2' log",
    "b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=": "Sectigo 'Mammoth' CT log",
    "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=": "Sectigo 'Sabre' CT log",
    "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=": "StartCom log",
    "FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=": "Symantec 'Sirius' log",
    "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=": "Symantec 'Vega' log",
    "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=": "Symantec log",
    "qNxS9j1rJCXlMeN89ORKcU8UKiCAOw0E0uLuBmR5SiM=": "Trust Asia CT2021",
    "Z422Wz50Q7bzo3DV4TqxtDvgoNNR98p0IlDHxvpRqIo=": "Trust Asia Log2021",
    "w2X5s2VPMoPHnamOk9dBj1ure+MlLJjh0vBLuetCfSM=": "Trust Asia Log2022",
    "6H6nZgvCbPYALvVyXT/g4zG5OTu5L79Y6zuQSdr1Q1o=": "Trust Asia Log2023",
    "AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=": "Venafi Gen2 CT log",
    "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=": "Venafi log",
    "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=": "WoSign log",
}

KNOWN_CERT_TYPES = {
    "2.23.140.1.1": "Extended validation TLS certificate",
    "2.23.140.1.2.1": "Domain validated TLS certificate",
    "2.23.140.1.2.2": "Organization validated TLS certificate",
}


@dataclass
class Host:
    host: Union[str, IPv4Address, IPv6Address]
    port: int

    def __str__(self) -> str:
        if isinstance(self.host, IPv6Address):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    @property
    def is_ip(self) -> bool:
        return isinstance(self.host, (IPv4Address, IPv6Address))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
@click.argument("host")
@click.option("--proxy", envvar="https_proxy", help="Proxy to use.")
@click.option("--servername", help="Custom SNI name to send in handshake.")
@click.option("--no-servername", is_flag=True, help="Do not send SNI in the handshake.")
@click.option("--print-pem", is_flag=True, help="Print certs in PEM format.")
@click.option(
    "--first-only", is_flag=True, help="Only process the first retrieved cert."
)
@click.option("--openssl-format", is_flag=True, help="Print cert info like OpenSSL.")
def main(
    host: str,
    proxy: Optional[str],
    servername: Optional[str],
    no_servername: bool,
    print_pem: bool,
    first_only: bool,
    openssl_format: bool,
) -> None:
    """Peeks at certificates exposed by other hosts."""
    if servername and no_servername:
        raise click.BadArgumentUsage(
            "--servername and --no-servername are mutually exclusive."
        )

    parsed_host = parse_host_input(host)

    if proxy:
        click.secho(f"Connecting via '{proxy}'", err=True)
        s = get_socket_via_proxy(proxy, parsed_host)
    else:
        click.secho(f"Connecting directly to host '{parsed_host}'", err=True)
        s = get_direct_socket(parsed_host)

    ctx = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(ctx, s)

    if not no_servername:
        if servername:
            conn.set_tlsext_host_name(servername.encode())
        else:
            # IP addresses are not permitted in servername
            # so only add if we are connecting to a DNS name.
            if not parsed_host.is_ip:
                conn.set_tlsext_host_name(str(parsed_host.host).encode())

    conn.set_connect_state()
    try:
        conn.do_handshake()
        conn.shutdown()
        conn.close()
    except SSL.Error as error:
        # If the host requires a client certificate
        # the handshake will fail, but we will still
        # get our certificate.
        ssl_error: Optional[SSL.Error] = error
    else:
        ssl_error = None

    certs = conn.get_peer_cert_chain()
    if not certs:
        click.secho(
            "Could not retrieve a certificate chain from the specified host: {}".format(
                ssl_error
            ),
            fg="red",
            err=True,
        )
        sys.exit(1)

    last_issuer = None
    for cert in certs:
        if openssl_format:
            click.echo(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode())
        else:
            last_issuer = print_cert_info(
                cert.to_cryptography(), servername or parsed_host.host, last_issuer
            )
        if print_pem:
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            click.echo(pem_cert.decode())

        if first_only:
            break


def parse_host_input(input: str) -> Host:
    # A bare IPv6 address can be confused
    # with a host:port combo, so let's try
    # to parse it as that first.
    try:
        return Host(ip_address(input), 443)
    except ValueError:
        pass

    parsed_host = urlsplit(input)
    if not parsed_host.netloc:
        parsed_host = urlsplit(f"//{input}")

    if not parsed_host.hostname:
        raise click.BadParameter("Invalid host specified")

    try:
        port = parsed_host.port
    except ValueError:
        raise click.BadParameter("Invalid port specified")

    if port is None:
        # default to 443, or whatever is default for the
        # specified schema (if we know it)
        port = 443
        if parsed_host.scheme:
            try:
                port = socket.getservbyname(parsed_host.scheme)
            except OSError:
                # unknown scheme
                pass

    try:
        return Host(ip_address(parsed_host.hostname), port)
    except ValueError:
        return Host(parsed_host.hostname, port)


def get_socket_via_proxy(proxy: str, host: Host) -> socket.socket:

    proxy_addr = urlsplit(proxy)
    if proxy_addr.scheme != "http":
        raise click.BadParameter("Only http proxies are supported")

    proxy_host = proxy_addr.hostname
    try:
        proxy_port = proxy_addr.port or 8080
    except ValueError:
        raise click.BadParameter("Invalid proxy port specified")

    if proxy_host is None:
        raise click.BadParameter("Invalid proxy specified")

    try:
        s = socket.create_connection((proxy_host, proxy_port))
    except socket.error as error:
        click.secho(f"Unable to connect to proxy {proxy}: {error}", fg="red", err=True)
        sys.exit(2)

    s.send(f"CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    try:
        proxy_response = s.recv(1024).decode()
        status_code = proxy_response.split("\r\n")[0].split(" ")[1]
    except (UnicodeDecodeError, IndexError):
        click.secho(f"Recieved invalid response from proxy {proxy}", fg="red", err=True)
        sys.exit(5)

    if status_code != "200":
        click.secho(f"Computer says no:\n{proxy_response}", fg="red", err=True)
        sys.exit(3)
    return s


def get_direct_socket(host: Host) -> socket.socket:
    try:
        s = socket.create_connection((str(host.host), host.port))
    except socket.error as error:
        click.secho(f"Unable to connect to {host}: {error}", fg="red", err=True)
        sys.exit(4)
    return s


def print_field(header: str, values: Iterable[Union[str, int, None]]) -> None:
    if values and any(values):
        click.secho("[{}]".format(header))
        for value in values:
            click.echo("  {}".format(value))


def get_log_names(scts: List[SignedCertificateTimestamp]) -> List[str]:
    names = []
    for sct in scts:
        names.append(KNOWN_LOGS.get(b64encode(sct.log_id).decode(), "Unknown log"))
    return names


def get_key_info(key: Any) -> str:
    if isinstance(key, RSAPublicKey):
        return "RSA ({})".format(key.key_size)
    if isinstance(key, EllipticCurvePublicKey):
        return "ECC ({})".format(key.key_size)
    return "Unknown"


def get_type(policies: List[PolicyInformation]) -> Optional[str]:
    for policy in policies:
        try:
            return KNOWN_CERT_TYPES[policy.policy_identifier.dotted_string]
        except KeyError:
            pass
    return None


def get_not_after_status(not_after: datetime) -> str:
    delta = (not_after - datetime.utcnow()).total_seconds()
    if delta < 0:
        text = click.style("Expired!", fg="red")
    elif delta < 2629743:
        # less than a month
        text = click.style("Expires soon!", fg="yellow")
    else:
        text = click.style("Valid", fg="green")

    return "{} ({})".format(not_after, text)


def get_hash_algorithm_name(cert: Certificate) -> Optional[str]:
    return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None


def name_matches_destination(
    name: GeneralName, destination: Union[str, IPv4Address, IPv6Address]
) -> bool:
    if name.value == destination:
        return True

    if isinstance(name.value, str) and isinstance(destination, str):
        # Working with domain names, not IPs - check for wildcard.
        return (
            name.value.startswith("*.")
            and destination.count(".") > 1  # can't have *.no
            and name.value.split(".", maxsplit=1)[1]
            == destination.split(".", maxsplit=1)[1]
        )

    return False


def print_cert_info(
    cert: Certificate,
    destination: Union[str, IPv4Address, IPv6Address],
    last_issuer: Optional[Name],
) -> Name:
    sans: List[str] = []
    scts: List[SignedCertificateTimestamp] = []
    policies: List[PolicyInformation] = []
    ekus: List[str] = []

    for ext in cert.extensions:
        if ext.oid.dotted_string == "2.5.29.17":
            for name in ext.value:
                if last_issuer is None and name_matches_destination(name, destination):
                    sans.append(click.style(str(name.value), fg="green"))
                else:
                    sans.append(str(name.value))
        elif ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.2":
            scts = [sct for sct in ext.value]
        elif ext.oid.dotted_string == "2.5.29.32":
            policies = ext.value
        elif ext.oid.dotted_string == "2.5.29.37":
            ekus = [eku._name for eku in ext.value]

    click.secho("#############################################################")

    print_field("Subject", [cert.subject.rfc4514_string()])
    print_field("Issuer", [cert.issuer.rfc4514_string()])
    print_field("Serial", [cert.serial_number])
    print_field("Key type", [get_key_info(cert.public_key())])
    print_field("Not before", [str(cert.not_valid_before)])
    print_field("Not after", [get_not_after_status(cert.not_valid_after)])
    print_field("SANs", sans)
    print_field("SCTs", get_log_names(scts))
    print_field("Type", [get_type(policies)])
    print_field("Extended Key Usages", ekus)
    print_field("Signature alg", [get_hash_algorithm_name(cert)])
    print_field("SHA1", [cert.fingerprint(hashes.SHA1()).hex()])
    print_field("SHA256", [cert.fingerprint(hashes.SHA256()).hex()])

    if cert.fingerprint(hashes.SHA256()).hex() in BAD_BUYPASS_CERTS:
        click.secho("This is a bad Buypass cert!", fg="red")

    if last_issuer is not None and last_issuer != cert.subject:
        click.secho("This cert is not the issuer of the previous cert", fg="red")

    if cert.issuer == cert.subject:
        click.secho("Self signed cert!", fg="red")

    click.echo()
    return cert.issuer


if __name__ == "__main__":
    main()
