import socket
import sys
from base64 import b64encode
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any
from urllib.parse import urlsplit

import click
import idna
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import (
    BasicConstraints,
    Certificate,
    GeneralName,
    PolicyInformation,
)
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp
from OpenSSL import SSL, crypto

__version__ = "2026.1.20"

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
    "R0RHfHXeQm1cRO/UqSyWd1l/ZXqP4MrbxtYW7aSXxCU=": "360 CT Log 2020",
    "xtftntuOdPCnG01KmEvL66u9KMwf12Mp6IcmzUwlRmM=": "360 CT Log 2021",
    "ZjywnB/Nm6pidjzLU07sgFgSKAUHrGmkX804z0zHTPE=": "360 CT Log 2022",
    "4mR/bto0BQPGTU4QqGloH96cWizzsy1fIAuWNgWQiCM=": "360 CT Log 2023",
    "xc/lS2FRtJsULtJjvecykzY3mXmVUK5ENc0aaZfJw8M=": "360 CT Log v1 2020",
    "SBRYfPKLCP5oP9K82UWZTC63TIroyH/OQpt80x1RvcQ=": "360 CT Log v1 2021",
    "SRG41hTP09mfFtN2VF7huMz8UR9QnwgLoKCH2R367qk=": "360 CT Log v1 2022",
    "tnQLEgAuAz/Q5+lB9Lo+4b/BSbUktM9ijVPv6h9AOo0=": "360 CT Log v1 2023",
    "lgbALGkAM6odFF9ZxuJkjQVJ8N+WqrjbkVpw2OzzkKU=": "Akamai",
    "sLeEvIHA3cR1ROiD8FmFu5B30TTYq4iysuUzmAuOUIs=": "Behind The Sofa",
    "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=": "CNNIC",
    "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=": "Certly",
    "ORpT9vlZkgxya++m6eVhlRlIazWCHo6bP8qCGYmzoW8=": "Cloudflare Cirrus",
    "H7w24ALt6X9AGZ6Gs1c7ikIX2AGHdGrQ2gOgYFTSDfQ=": "Cloudflare Nimbus 2017",
    "23Sv7ssp7LH+yj5xbSzluaq7NveEcYPHXZ1PN7Yfv2Q=": "Cloudflare Nimbus 2018",
    "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFY=": "Cloudflare Nimbus 2019",
    "Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=": "Cloudflare Nimbus 2020",
    "RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=": "Cloudflare Nimbus 2021",
    "QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=": "Cloudflare Nimbus 2022",
    "ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=": "Cloudflare Nimbus 2023",
    "2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=": "Cloudflare Nimbus 2024",
    "zPsPaoVxCWX+lZtTzumyfCLphVwNl422qX5UwP5MDbA=": "Cloudflare Nimbus 2025",
    "yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=": "Cloudflare Nimbus 2026",
    "TGPcmOWcHauI9h6KPd6uj6tEozd7X5uUw/uhnPzBviY=": "Cloudflare Nimbus 2027",
    "Bi6kUhAOkC/jzO7lk9/B86nFBj5yT7GiMFPPIGtLM+s=": "Cloudflare Raio 2025h2a",
    "Tw05u8NV28wWJ5ZuVAUVfMr3Lj90j0f+ewSeWlkVXL0=": "Cloudflare Raio 2025h2b",
    "5bvNwMctaSvZWYo2AgQ86FTsb2D4AGZ4WWOIK3w4JDg=": "Cloudflare Raio 2026h1a",
    "uuKpKTLFwF0fpU00gTDwm/yIMxZKFaH7vvUmKDJWyAs=": "Cloudflare Raio 2026h2a",
    "ijgQv0CPWs97dN4gwHGQO3F5yrDb12jv+hD2KY6gaAw=": "Cloudflare Raio 2027h1a",
    "Ia1IGvXLVPNLOr+uoP8Gmns8dm/DtpCHC7RrFS+2C/k=": "Cloudflare Raio 2027h2a",
    "7DSwkhPo35hYEZa4DVlPq6Pm/bG4aOw/kqhHvYd6z/k=": "Cloudflare Research cftest2025h1a",
    "2KJiliJSBM2181NJWC5O1mWiRRsPJ6i2iWE2s7n8Bwg=": "Cloudflare Research cftest2025h2a",
    "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=": "DigiCert",
    "h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=": "DigiCert 2",
    "VVlTrjCWAIBs0utSCKbJnpMYKKwQVrRCHFU2FUxfdaw=": "DigiCert Gorgon",
    "b/FBtWR+QiL37wUs7658If1gjifSr1pun0uKN9ZjPuU=": "DigiCert Nessie 2018",
    "/kRhCLHQGreKYsz+q2qysrq/86va2ApNizDfLQAIgww=": "DigiCert Nessie 2019",
    "xlKg7EjOs/yrFwmSxDqHQTMJ6ABlomJSQBujNioXxWU=": "DigiCert Nessie 2020",
    "7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=": "DigiCert Nessie 2021",
    "UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=": "DigiCert Nessie 2022",
    "s3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZo=": "DigiCert Nessie 2023",
    "c9meiRtMlnigIH1HneayxhzQUV5xGSqMa4AQesF3crU=": "DigiCert Nessie 2024",
    "5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlA=": "DigiCert Nessie 2025",
    "2wds3mqLeOxY1gVklutqJqjFnnISk+isAyfd3onbWio=": "DigiCert Sphinx 2024h1",
    "3Mleb6KZubD9vWymo24dcsQhL90eD0dVOjbWzxrRHY0=": "DigiCert Sphinx 2024h2",
    "3oWB11AkfGvNy69WN8XngcZM5G7WF2OfjzSnJsnivTc=": "DigiCert Sphinx 2025h1",
    "pELFBklgYVSPD9TqnPt6LSZFTYepfy/fRVn2J086hFQ=": "DigiCert Sphinx 2025h2",
    "SZybad4dfOz8Nt7Nh2SmuFuvCoeAGdFVUvvp6ynd+MM=": "DigiCert Sphinx 2026h1",
    "lE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9VTcuGdg=": "DigiCert Sphinx 2026h2",
    "RqI5Z8YNtkaHxm89+ZmUdpOmphEghFfVVefj0KHZtkY=": "DigiCert Sphinx 2027h1",
    "H7D4qS2K3aEhd2wF4qouFbrLxitlOTaVV2qqtS4R0R0=": "DigiCert Sphinx 2027h2",
    "tp3cvDwave9vn9YMiLEGe3fwgmiLLXhl0Es5q+knpXU=": "DigiCert Wyvern 2024h1",
    "DCrvLEpbmIPU3aOC/lD7UYiz6XMzoexToJ3Jp50NCCA=": "DigiCert Wyvern 2024h2",
    "cyAiDwgWivnzxKaLCrJqmkoA7vV3hYoITQUA1KVCRFk=": "DigiCert Wyvern 2025h1",
    "7TxL1ugGwqSiAFfbyyTiOAHfUS/txIbFcA8g3bc+P+A=": "DigiCert Wyvern 2025h2",
    "ZBHEbKQS7KeJHKICLgC8q08oB9QeNSer6v7VA8l9zfA=": "DigiCert Wyvern 2026h1",
    "wjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0=": "DigiCert Wyvern 2026h2",
    "ABpdGhwtk3W2SFV4+C9xoa5u7zl9KXyK4xV7yt7hoB4=": "DigiCert Wyvern 2027h1",
    "N6oHzCFvLm2RnHCdJNj3MbAPKxR8YhzAkaX6GoTYFt0=": "DigiCert Wyvern 2027h2",
    "wRZK4Kdy0tQ5LcgKwQdw1PDEm96ZGkhAwfoHUWT2M2A=": "DigiCert Yeti 2018",
    "4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4=": "DigiCert Yeti 2019",
    "8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=": "DigiCert Yeti 2020",
    "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=": "DigiCert Yeti 2021",
    "IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=": "DigiCert Yeti 2022",
    "BZwB0yDgB4QTlYBJjRF8kDJmr69yULWvO0akPhGEDUo=": "DigiCert Yeti 2022 #2",
    "Nc8ZG7+xbFe/D61MbULLu7YnICZR6j/hKu+oA8M71kw=": "DigiCert Yeti 2023",
    "SLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHM=": "DigiCert Yeti 2024",
    "fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebg=": "DigiCert Yeti 2025",
    "cX6nQgl1voSicjVT8Xd8Jt1Rr04QIUQJTZAZtGL7Zmg=": "GDCA 1",
    "FDCNkMzQMBNQBcAcpSbYHoTodiTjm2JI4I9ySuo7tCo=": "GDCA 2",
    "8bpXJlnIJLUefb3hMuILQRzibfIGUezCCiwLOk4kL/0=": "GDCA 2 (Old Key)",
    "yc+JCiEQnGZswXo+0GXJMNDgE1qf66ha8UIQuAckIao=": "GDCA Old 1",
    "kkow+Qkzb/Q11pk6EKx1osZBco5/wtZZrmGI/61AzgE=": "GDCA Old 2",
    "5Pt3SiEkxYZAsYMvUKv63ISjiu1xke62aSI3ksv2KJE=": "Geomys Navigli 2025h2",
    "gs3NR5535F0UrWkDiCxBE/yBwhITvsKz2U6dx82Azf4=": "Geomys Navigli 2026h1",
    "JKaah8LdWC3VArJRfww4J/MLTqhKJBO1U+b78YzxX+8=": "Geomys Navigli 2026h2",
    "2tZHUVKWGUn6T3McZw6F5eS3TgaIGWBT8Rha1ySUGtM=": "Geomys Navigli 2027h1",
    "z14MRaO4fEHLthgI+OCQulvrTdMmwUBN/7at+Y4WaRY=": "Geomys Navigli 2027h2",
    "750EQi4gtDIQJ1TfUtJRRgJ/hEwH/YZeySLub86fe7w=": "Geomys Tuscolo 2025h2",
    "cX6V88I4im2x44RJPTHhWqliCHYtQgDgBQzQZ7WmYeI=": "Geomys Tuscolo 2026h1",
    "Rq+GPTs+5Z+ld96oJF02sNntIqIj9GF3QSKUUu6VUF8=": "Geomys Tuscolo 2026h2",
    "WW5sM4aUsllyolbIoOjdkEp26Ag92oc7AQg4KBQ87lk=": "Geomys Tuscolo 2027h1",
    "1d5V7roItgyf/BjFE75qYLoARga8WVuWu0T2LMV9Ofo=": "Geomys Tuscolo 2027h2",
    "+tTJfMSe4vishcXqXOoJ0CINu/TknGtQZi/4aPhrjCg=": "Google Argon 2017",
    "pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU=": "Google Argon 2018",
    "Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=": "Google Argon 2019",
    "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=": "Google Argon 2020",
    "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=": "Google Argon 2021",
    "KXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4Q=": "Google Argon 2022",
    "6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=": "Google Argon 2023",
    "7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=": "Google Argon 2024",
    "TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=": "Google Argon 2025h1",
    "EvFONL1TckyEBhnDjz96E/jntWKHiJxtMAWE6+WGJjo=": "Google Argon 2025h2",
    "DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=": "Google Argon 2026h1",
    "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=": "Google Argon 2026h2",
    "1tWNqdAXU/NqSqDHV0kCr+vH3CzTjNn3ZMgMiRkenwI=": "Google Argon 2027h1",
    "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=": "Google Aviator",
    "w78Dp+HKiEHGB7rj/0Jw/KXsRbGG675OLPP8d4Yw9fY=": "Google Crucible",
    "HQJLjrFJizRN/YfqPvwJlvdQbyNdHUlwYaR3PEOcJfs=": "Google Daedalus",
    "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=": "Google Icarus",
    "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=": "Google Pilot",
    "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=": "Google Rocketeer",
    "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=": "Google Skydiver",
    "UutLIl7IlpdIUGdfI+Q7wdAh4yFM5S7NX6h8IDzfygM=": "Google Solera 2018",
    "C3YOmouaaC+ImFsV6UdQGlZEa7qIMHhcOEKZQ4ZFDAA=": "Google Solera 2019",
    "H8cs5aG3mfQAw1m/+WyjkTVI6GRCIGEJUum6F3T3usc=": "Google Solera 2020",
    "o8mYRegKt84AFXs3Qt8CB90nKytgLs+Y7iwS25xa5+c=": "Google Solera 2021",
    "aXqvyhprU2+uISBQRt661+Dq6hPSQy5unY+zefK5qvM=": "Google Solera 2022",
    "+X6XuNM+96FZAqU6GeF5kOXcQGoDGCW6rZPpj5ucacs=": "Google Solera 2023",
    "MCTOfusWiGJyS+pwLv/5ks/kVkNBkapZWyX4AibIABc=": "Google Solera 2024",
    "P+HLRu1HNXmvAUH5ck2dxENHLXVuhedxnFWCSF3U4eQ=": "Google Solera 2025h1",
    "JgI5SIdM9/zQ+2RxpD6EfrsgCubi+iQjbfbRpgZjD7E=": "Google Solera 2025h2",
    "yEuQege+qimmFMJFhLej9mJDlGh7Jf5ig4tx7EIq0vk=": "Google Solera 2026h1",
    "YukAYASjB5VadUS01YSpYmjKHW5Fha3wkW3+X9wfBNs=": "Google Solera 2026h2",
    "PeSSqJiTrXBeeEbtIdSNyvutE56mTtHjSfkAsKLNpeI=": "Google Solera 2027h1",
    "v4vLUgreyaZJbsQJYM1zN+YKJbfu0ef6TGSJJcd2h2s=": "Google Staging Arche 2025h1",
    "L2UYNygi6ysgrNQ0osu5ivLTWAzifbdx/LfHcYDhOi4=": "Google Staging Arche 2025h2",
    "J+sqNJffaHpkC2Q4TkhW/Nyj6H+NzWbzTtbxvkKB7fw=": "Google Staging Arche 2026h1",
    "qJnYeAySkKr0YvMYgMz71SRR6XDQ+/WR73Ww2ZtkVoE=": "Google Submariner",
    "sMyD5aX5fWuvfAnMKEkEhyrH6IsTLGNQt8b9JuFsbHc=": "Google Test Tube",
    "sQzVWabWeEaBH335pRUyc5rEjXA76gMj2l04dVvArU4=": "Google Xenon 2018",
    "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=": "Google Xenon 2019",
    "B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw=": "Google Xenon 2020",
    "fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=": "Google Xenon 2021",
    "RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=": "Google Xenon 2022",
    "rfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgoo=": "Google Xenon 2023",
    "dv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQ=": "Google Xenon 2024",
    "zxFW7tUufK/zh1vZaS6b6RpxZ0qwF+ysAdJbd87MOwg=": "Google Xenon 2025h1",
    "3dzKNJXX4RYF55Uy+sef+D0cUN/bADoUEnYKLKy7yCo=": "Google Xenon 2025h2",
    "lpdkv1VYl633Q4doNwhCd+nwOtX2pPM2bkakPw/KqcY=": "Google Xenon 2026h1",
    "2AlVO5RPev/IFhlvlE+Fq7D4/F6HVSYPFdEucrtFSxQ=": "Google Xenon 2026h2",
    "RMK9DOkUDmSlyUoBkwpaobs1lw4A7hEWiWgqHETXtWY=": "Google Xenon 2027h1",
    "gKS9UgzUVxLVQ+kCRE2vl3L6PxJdszEOUvRFH2iLYe0=": "Google staging Badpreissuer 2026h2",
    "GoudanQ8ze1gH3O9MJcIHbyuxKYTnJKwtUDDE3sg7AU=": "IPng Gouda 2025h2",
    "GoudaUpXmMiZoMqIvfSPwLRWYMzDYA0fcfRp/8fRrKM=": "IPng Gouda 2026h1",
    "Goudaw/+v4G0eTnG0jEKhtbRAtTwRuIYLJ3jX14mJe8=": "IPng Gouda 2026h2",
    "Gouda43XkdHNBUnttgNV1ga2T60w23H+eI8Px8j7xLE=": "IPng Gouda 2027h1",
    "GoudaVNi2GSSp7niI2BuNOzp4xC6NPuTBXhdKc5XV+s=": "IPng Gouda 2027h2",
    "+3xjpo0eBq3Qg4ibuNQyHLJFROv2/mlyKRkuOD5ebiM=": "IPng Halloumi 2025h2",
    "fz035/iSPY5xZb6w0+q+5yoivkbAy4TEFtTkuYJky8I=": "IPng Halloumi 2026h1",
    "YKWe2Ffs01lJBV7vitDrq2CYZIALz1+41gv1v/87FMU=": "IPng Halloumi 2026h2",
    "JuNkblhpISO8ND9HJDWbN5LNJFqI2BXTkzP9mRirRyM=": "IPng Halloumi 2026h2a",
    "ROgi/CurDpLu0On61pZkYCd20Bdg4IkFCckjobA/w38=": "IPng Halloumi 2027h1",
    "CRV/Yy1Gx/dtlSZUk7wPALOVrF2zorJr+wQ9ukrGOJM=": "IPng Halloumi 2027h2",
    "+aEI1Vq8bDZUG/1vReL3fh66SuI7WN/b7i2cu11WxTo=": "IPng Lipase 2025h2",
    "b8whyKsJkXnvusRMwpnQ7EENf77I4306CVV2zZ9jxgg=": "IPng Lipase 2026h1",
    "wrITHXl+UNevVCq6lNe/gvkblit8VSpx1d6TA3oaZHo=": "IPng Lipase 2026h2",
    "lobDwHKqsHMHbjlGc7fpkBd6BWGOonZNS6ZQqQ6eCMw=": "IPng Lipase 2027h1",
    "vDvULt2EjVnlRf/XkJcMGs3KpHmmbmmVMI49ZsSR/kA=": "IPng Lipase 2027h2",
    "IPng43glrS2aHdKilIAgicJdQ80udPGVttwMe+uE2ZM=": "IPng Rennet 2025h2",
    "IPng7N+kfJEgOWLvg8kCWPeQbZ03SYvh/9hJVBcyCyA=": "IPng Rennet 2026h1",
    "IPngiezr0NlfrYnreI+2QK/E2J+7QNyCETQxnDW/CNo=": "IPng Rennet 2026h2",
    "IPngmrbD1ZzKxMv9sDFnjmgsvhhIV4z/L8d05K0vULE=": "IPng Rennet 2027h1",
    "IPngONeE+PfIWiV4c8W5xL8kvQJlq9F3lPXT32yFW6s=": "IPng Rennet 2027h2",
    "yLkilxtwEtRI1qd7fACK5qViNNxRkxAzwlUNQjiVeZo=": "Itko 2025",
    "mBGudl5g4O7Und9cVLLj8utfINvxaLeJs8EJgQZqzrY=": "Itko Alpha",
    "dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM=": "Izenpe",
    "iUFEnHB0Lga5/JznsRa6ACSqNtWa9E8CBEBPAPfqhWY=": "Izenpe Argi",
    "KWr6LVaLyg0uqESVaulyH8Nfo1Xs2plpOq/UWKca790=": "Let's Encrypt Clicky",
    "ZZszUPQ7EsxepatOx2XT/ebIgkN3d3jnIAP56yuMMSk=": "Let's Encrypt Oak 2019",
    "5xLysDd+GmL7jskMYYTx6ns3y1YdESZb8+DzS/JBVG4=": "Let's Encrypt Oak 2020",
    "lCC8Ho7VjWyIcx+CiyIsDdHaTV5sT5Q9YdtOL1hNosI=": "Let's Encrypt Oak 2021",
    "36Veq2iCTx9sre64X04+WurNohKkal6OOxLAIERcKnM=": "Let's Encrypt Oak 2022",
    "tz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJk=": "Let's Encrypt Oak 2023",
    "O1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61Bc=": "Let's Encrypt Oak 2024h1",
    "PxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4=": "Let's Encrypt Oak 2024h2",
    "ouMK5EXvva2bfjjtR2d3U9eCW4SU1yteGyzEuVCkR+c=": "Let's Encrypt Oak 2025h1",
    "DeHyMCvTDcFAYhIJ6lUu/Ed0fLHX6TDvDkIetH5OqjQ=": "Let's Encrypt Oak 2025h2",
    "GYbUxyiqb/66A294Kk0BkarOLXIxD67OXXBBLSVMx9Q=": "Let's Encrypt Oak 2026h1",
    "rKswcGzr7IQx9BPS9JFfER5CJEOx8qaMTzwrO6ceAsM=": "Let's Encrypt Oak 2026h2",
    "Iy1BpM2sh87Z+UP0aMKCCVrgnTDWLi+mXdw7kZwuRo8=": "Let's Encrypt Sapling 2022h2",
    "wYMkC/GkUMdvuwByadysO+IqSAXU2+BJZsPIq8RHsAw=": "Let's Encrypt Sapling 2023h1",
    "7audHd2Dc5Wf9SqI5Gu0vMPEzE12imDM/042LX+41mg=": "Let's Encrypt Sapling 2023h2",
    "qmywxcn0xJ2NjqkMORfg1wrZIhC/BX9BUJOCzDUMmEY=": "Let's Encrypt Sapling 2024h1",
    "hRuuju4zwbmHP8ScenwnZWY7a4BjAwQK7KbBEaWr6dc=": "Let's Encrypt Sapling 2024h2",
    "TgJ3oMtvarf2feceaghbLRgMKXeCS/tMK72dLNQR874=": "Let's Encrypt Sycamore 2025h1b",
    "94/yCGmtl2pDc7SsqLOyAxSOFO3mi+FBU1uhNot7qAY=": "Let's Encrypt Sycamore 2025h2b",
    "W/beU/H7+sSaGFl0aUWhpqconV5wpg9IRQ5Ya7mucrg=": "Let's Encrypt Sycamore 2025h2d",
    "pcl4kl1XRheChw3YiWYLXFVki30AQPLsB2hR0YhpGfc=": "Let's Encrypt Sycamore 2026h1",
    "bP5QGUOoXqkWvFLRM+TcyR7xQRx9JYQg0XOAnhgY6zo=": "Let's Encrypt Sycamore 2026h2",
    "jspHC6zeavOiBrCkeoS3Rv4fxr+VPiXmm07kAkjzxug=": "Let's Encrypt Sycamore 2027h1",
    "5eNiR9ku9K2jhYO1NZHbcp/C8ArktnRRdNPd/GqiU4g=": "Let's Encrypt Sycamore 2027h2",
    "hJ9ff1jSv3tU7L10YRzqRcScmPHWSBvG9p6MF08k888=": "Let's Encrypt Testflume 2019",
    "xj8iGMN9VqaqBrWW2o5T1NcVbR6brI5E0iAt5k1p2dw=": "Let's Encrypt Testflume 2020",
    "A+3x2pd2tvOMNB457Z1wenVwNpz5hE8yf+nhQTg2G2A=": "Let's Encrypt Testflume 2021",
    "Iyfv2jUlENvAGe9JGuP/HMWkebzjeHg2DuMYz/tk+Mg=": "Let's Encrypt Testflume 2022",
    "VTS3q1pqw6fL66ZUh7Ki1xtI9lD6F8UZfJegyyB288Y=": "Let's Encrypt Testflume 2023",
    "lZC9hfLPxQZJmKurW7JsLnoXZwKRHBO2i0gF4euUJ+8=": "Let's Encrypt Twig 2025h1b",
    "wF0gVDhcss+yF5INLw3Hg1JhR7GqT++Xynjh8LuE/O0=": "Let's Encrypt Twig 2025h2b",
    "ZxpEGzT2LEwVmemmpoGbETpNRbH+Sm03TrLlKwGs4z4=": "Let's Encrypt Twig 2025h2d",
    "WUSCTUXhQ2fKUHvFtaSmfyox7je4S+Qnx6+LKKVk0Ss=": "Let's Encrypt Twig 2026h1",
    "xn2BnpPBLPrrX2WgTQja4wqOXCf7fRUc73xH4tXLHe0=": "Let's Encrypt Twig 2026h2",
    "MIQn6dbJsGQ5/rsS4QFNbqJ2NlTgQ19Z48RWY2ZbuOo=": "Let's Encrypt Twig 2027h1",
    "0UNvAl0dnyOdvMGLuf+ksRm5lU1hDIPr7KA1oVaWvYE=": "Let's Encrypt Twig 2027h2",
    "IX7IijpQPODOtMQx74xNVMHVjB9SuiP0KekrE2jAgWE=": "Let's Encrypt Willow 2025h1b",
    "5e8hdnsVqhuSh8Bn9rml8aUjEHJ9u4on/u6dHIdJ27g=": "Let's Encrypt Willow 2025h2b",
    "kqECxXwi2rGMzCrnH9TMWcBdJR2hbHPiKBvT8LBImIc=": "Let's Encrypt Willow 2025h2c",
    "5NAXdhyRORG+9HOWrNjSRljCT7WTtRvqxVknYuiFPBU=": "Let's Encrypt Willow 2025h2d",
    "4yON8o2iiOCq4Kzw+pDJhfC2v/XSpSewAfwcRFjEtug=": "Let's Encrypt Willow 2026h1",
    "qCbL4wrGNRJGUz/gZfFPGdluGQgTxB3ZbXkAsxI8VSc=": "Let's Encrypt Willow 2026h2",
    "ooEAGHNOF24dR+CVQPOBulRml81jqENQcW64CU7a8Q0=": "Let's Encrypt Willow 2027h1",
    "ppWirZJtb5lujvxJAUJX2LvwRqfWJYm4jcLXh2x45S8=": "Let's Encrypt Willow 2027h2",
    "ObmHiCgZXzstDRtIFKOujA0B/khiId1pOX1294V0EcM=": "MerkleMap CompactLog",
    "jJykryzVPQzdSO/Z7DjWWmfbvWZcIVoCuvebWUljuG0=": "MerkleMap CompactLog (old)",
    "KrgwRDO5FN7S8x5CB/JRwXo3oJJoUtkIAgb4Xlc5Fio=": "Mozilla Test EC Log",
    "VCIlmPM9NkgFQtrs4Oa5TeFcDu6MWRTKSNdePEhOgD8=": "Mozilla Test RSA Log 1",
    "MQj2tt1yGAfwFpWETYUCVrZxk2CD2705NKBQUlAaKJI=": "Mozilla Test RSA Log 2",
    "6Mz6YX3GS9LYtKJsKw/1dnHx5n3gb4uVYfJVLXuUA5o=": "Mozilla Test RSA Log 4",
    "U3tpo1ZDNanASQTjlZOywpjrjXpugwI2NcYnJIzWtEA=": "NORDUnet Flimsy",
    "qucLfzy41WbIbC8Wl5yfRF9pqw60U1WJsvd6AwEE880=": "NORDUnet Plausible",
    "4BJ2KekEllZOPQFHmESYqkj4rbFmAOt5AqHvmQmQYnM=": "PuChuangSiDa 1",
    "/RySG7GQgPWKaB4qwcUH/rlyaR0Z81ZsKnqsfh+9574=": "Rome 2024h2",
    "CcqE9Qr4S0I/k8n/aw7Zb50vFLK8N6VTDklIYnKaIrU=": "Rome 2025h1",
    "/gPlcjs96uJwbyD9J6XweM1hKgw5HI7W9mQBaPN3e1U=": "Rome 2025h2",
    "MtxZwtTEGWjVbhS8YayPDkXbOfrzwVWqQlL1AB+gxiM=": "SHECA",
    "z1XiiSNJfDQNUgbQU1Ouslg0tS8fjclSaAnyEu/dfKY=": "SHECA Old",
    "z7mcDrSm+UpUkOIRc82e/fPg5uj5NN6F3OBCKnroq4w=": "SM2 CT log 1",
    "Tbp5eO+1TY58gsVfvTdYnoVdqxb4aAym6z/Pgeb3Y3U=": "SM2 CT log 2",
    "Zddg4iz9kzYbBCn5I+feCu/d0203Bt8II8UL57WvPf4=": "SM2 CT log 3",
    "OTdvVF97Rgf1l0LXaM1dJDe/NHO2U0pINLz3Lmgcg8k=": "SSLWatcher.com Alpha",
    "23b9raxl59CVCIhuIVm9i5A1L1/q0+PcXiLrNQrMe5g=": "Sectigo Dodo",
    "YaNdw5gGGypZW/40RomVGPD+rBSwG+Aqk78FIUY6nb0=": "Sectigo Dumbo",
    "DR28iUTp9QBVQtctPhRMzEMIKrbqHpTf1wZlfS6G8wE=": "Sectigo Elephant 2025h2",
    "0W6ppWgHfmY1oD83pd28A6U8QRIU1IgY9ekxsyPLlQQ=": "Sectigo Elephant 2026h1",
    "r2eIO1ewTt2Pptl+9i6o64EKx3Fg8CReVdYML+eFhzo=": "Sectigo Elephant 2026h2",
    "YEyar3p/d18B1Ab8kg3ImesLHH34yVIb+voXdzuXi8k=": "Sectigo Elephant 2027h1",
    "okkM3NuOM6QAMhdg1tTVGiA2GR6nfZaL4mqKAPb///c=": "Sectigo Elephant 2027h2",
    "b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=": "Sectigo Mammoth",
    "KdA6G7Z0qnEc0wNbZVfBT4qni0/oOJRJ7KRT+US9JGg=": "Sectigo Mammoth 2024h1",
    "UIUBWNy2BZXADpKoEQLszf4/a3hYQp9XmDU4ydpSUGM=": "Sectigo Mammoth 2024h1b",
    "3+FW66oFr7WcD4ZxjajAMk6uVtlup/WlagHRwTu+Ulw=": "Sectigo Mammoth 2024h2",
    "E0rfGrWYQgl4DG/vTHqRpBa3I0nOWFdq367ap8Kr4CI=": "Sectigo Mammoth 2025h1",
    "rxgaKNaMo+CpikycZ6sJ+Lu8IrquvLE4o6Gd0/m2Aw0=": "Sectigo Mammoth 2025h2",
    "JS+Uwisp6W6fQRpyBytpXFtS/5epDSVAu/zcUexN7gs=": "Sectigo Mammoth 2026h1",
    "lLHBirDQV8R74KwEDh8svI3DdXJ7yVHyClJhJoY7pzw=": "Sectigo Mammoth 2026h2",
    "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=": "Sectigo Sabre",
    "ouK/1h7eLy8HoNZObTen3GVDsMa1LqLat4r4mm31F9g=": "Sectigo Sabre 2024h1",
    "GZgQcQnw1lIuMIDSnj9ku4NuKMz5D1KO7t/OSj8WtMo=": "Sectigo Sabre 2024h2",
    "4JKz/AwdyOdoNh/eYbmWTQpSeBmKctZyxLBNpW1vVAQ=": "Sectigo Sabre 2025h1",
    "GgT/SdBUHUCv9qDDv/HYxGcvTuzuI0BomGsXQC7ciX0=": "Sectigo Sabre 2025h2",
    "VmzVo3a+g9/jQrZ1xJwjJJinabrDgsurSaOHfZqzLQE=": "Sectigo Sabre 2026h1",
    "H1bRq5RwSkHdP+r99GmTVTAsFDG/5hNGCJ//rnldzC8=": "Sectigo Sabre 2026h2",
    "XKV30pt/i69Bntjsq/tty67DhTcC1XRvF02tPJNKqWo=": "Sectigo Tiger 2025h2",
    "FoMtq/CpJQ8P8DqlRf/Iv8gj0IdL9gQpJ/jnHzMT9fo=": "Sectigo Tiger 2026h1",
    "yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5o=": "Sectigo Tiger 2026h2",
    "HJ9oLOn68EVpUPgbloqH3dsyENhM5siy44JSSsTPWZ8=": "Sectigo Tiger 2027h1",
    "A4AqwmL24F4D+Lxve5hRMk/Xaj31t1lRdeIi+46b1fY=": "Sectigo Tiger 2027h2",
    "48P4ZZ9FWlaBsgxwPWjmpDA1KDM1oETUupNyRzWtBas=": "Sectigo Tigger 2025",
    "vjHTZYjf2AXIbTUgKYSsyapEruOECAufz0LryHNV5Js=": "Sectigo Tigger 2026",
    "+mMSdJrcyBmVTj7zAR1CZ3aI1Ecc/vY1P4kdyHwSrNQ=": "Sectigo Tigger 2027",
    "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=": "StartCom",
    "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=": "Symantec",
    "p85KTmIH4K3e5f2qSx+GdodntdACpV1HMQ5+ZwqV6rI=": "Symantec Deneb",
    "FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=": "Symantec Sirius",
    "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=": "Symantec Vega",
    "pZWUO1NwvukG4AUNH7W7xqQOZfJlroUsdjY/rbIzNu0=": "TrustAsia 2020",
    "Z422Wz50Q7bzo3DV4TqxtDvgoNNR98p0IlDHxvpRqIo=": "TrustAsia 2021",
    "w2X5s2VPMoPHnamOk9dBj1ure+MlLJjh0vBLuetCfSM=": "TrustAsia 2022",
    "6H6nZgvCbPYALvVyXT/g4zG5OTu5L79Y6zuQSdr1Q1o=": "TrustAsia 2023",
    "MG0pV2rSGp1K4SrK2KqKeDqmWjIRYKz/Ww7uTKMgHQU=": "TrustAsia 2024",
    "qNxS9j1rJCXlMeN89ORKcU8UKiCAOw0E0uLuBmR5SiM=": "TrustAsia CT2021",
    "h0+1DcAp2ZMd5XPp8omejkUzs5LTiwpGJXS/D+6y/B4=": "TrustAsia CT2024",
    "KOKBOP2DIUXpqdaqdTdtg3eohRKzwH9yQUgh3L3pjGY=": "TrustAsia CT2025A",
    "KCyL3YEP+QkSCs4W1uDsIBvqgqOkrxnZ7/tZ6D/cQmg=": "TrustAsia CT2025B",
    "dNudWPfUfp39eHoWKpkcGM9pjafHKZGMmhiwRQ26RLw=": "TrustAsia CT2026A",
    "Jbfv3qETAZPtkweXcKoyKiZiDeNayKp8dRl94LGp4GU=": "TrustAsia CT2026B",
    "7drrgVxjITRJtHvlB3kFq9DZMUfCesUUazvFjkPptsc=": "TrustAsia HETU 2027",
    "RTWUmNk6ieAoAwjTfWJtxCN1R1jc4DcANvurDt+Ka88=": "TrustAsia Log1",
    "VzRIzG4dLA3JS2nyh9Hv5IPHolxQxTILuzrep29usEE=": "TrustAsia Luoshu 2027",
    "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=": "Venafi",
    "AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=": "Venafi Gen2",
    "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=": "WoSign",
    "Y9AAYCbd4QuwYB9FJEaWXuK26izU+8layGalUK+Qdbc=": "WoSign 2",
    "bQEsfZvOgPjWivKco5/77P+UE+JMZ1TZcPipZ2bnJhk=": "WoSign 3",
    "nk/3PcPOIgtpIXyJnkaAdqv414Y21cz8haMadWKLqIs=": "WoSign Old",
    "oXEni6iuir1G4jqDj74jdM4lWBrNpUBslrhxAEfpvsI=": "WoTrus",
    "mueOgrUnqTLVe4NZadQv4/Ah4TKZis8cN3oV+x5FLFo=": "WoTrus 3",
}

KNOWN_CERT_TYPES = {
    "2.23.140.1.1": "Extended validation TLS certificate",
    "2.23.140.1.2.1": "Domain validated TLS certificate",
    "2.23.140.1.2.2": "Organization validated TLS certificate",
}


@dataclass
class Host:
    host: str | IPv4Address | IPv6Address
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
    proxy: str | None,
    servername: str | None,
    *,
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
        ssl_error: SSL.Error | None = error
    else:
        ssl_error = None

    certs = conn.get_peer_cert_chain()
    if not certs:
        click.secho(
            f"Could not retrieve a certificate chain from the specified host: {ssl_error}",
            fg="red",
            err=True,
        )
        sys.exit(1)
        return  # https://github.com/astral-sh/ty/issues/690

    last_cert = None
    for cert in certs:
        if openssl_format:
            click.echo(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode())
        else:
            last_cert = print_cert_info(
                cert.to_cryptography(), servername or parsed_host.host, last_cert
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
    except ValueError as ve:
        raise click.BadParameter("Invalid port specified") from ve

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
        pass

    if parsed_host.hostname.isascii():
        return Host(parsed_host.hostname, port)

    return Host(idna.encode(parsed_host.hostname).decode(), port)


def get_socket_via_proxy(proxy: str, host: Host) -> socket.socket:
    proxy_addr = urlsplit(proxy)
    if proxy_addr.scheme != "http":
        raise click.BadParameter("Only http proxies are supported")

    proxy_host = proxy_addr.hostname
    try:
        proxy_port = proxy_addr.port or 8080
    except ValueError as ve:
        raise click.BadParameter("Invalid proxy port specified") from ve

    if proxy_host is None:
        raise click.BadParameter("Invalid proxy specified")

    try:
        s = socket.create_connection((proxy_host, proxy_port))
    except OSError as error:
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
    except OSError as error:
        click.secho(f"Unable to connect to {host}: {error}", fg="red", err=True)
        sys.exit(4)
    return s


def print_field(header: str, values: Iterable[str | int | None]) -> None:
    if values and any(values):
        click.secho(f"[{header}]")
        for value in values:
            click.echo(f"  {value}")


def get_log_names(scts: list[SignedCertificateTimestamp]) -> list[str]:
    names = []
    for sct in scts:
        names.append(KNOWN_LOGS.get(b64encode(sct.log_id).decode(), "Unknown log"))
    return names


def get_key_info(key: Any) -> str:
    if isinstance(key, RSAPublicKey):
        return f"RSA ({key.key_size})"
    if isinstance(key, EllipticCurvePublicKey):
        return f"ECC ({key.curve.name})"
    return "Unknown"


def get_type(policies: list[PolicyInformation], *, is_ca: bool) -> str | None:
    for policy in policies:
        try:
            usage = KNOWN_CERT_TYPES[policy.policy_identifier.dotted_string]
        except KeyError:
            continue

        if is_ca:
            return f"CA that issues {usage}s"
        return usage

    return None


def get_local_datetime(dt: datetime) -> str:
    """
    Takes a timezone aware datetime, and returns
    it as a string in the local timezone.
    """
    return str(dt.astimezone())


def get_not_before(cert: Certificate) -> datetime:
    try:
        # cryptography >= 42
        return cert.not_valid_before_utc
    except AttributeError:
        # cryptography < 42
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def get_not_after(cert: Certificate) -> datetime:
    try:
        # cryptography >= 42
        return cert.not_valid_after_utc
    except AttributeError:
        # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def get_not_after_status(cert: Certificate) -> str:
    not_after = get_not_after(cert)
    not_before = get_not_before(cert)
    lifetime = not_after - not_before

    if lifetime < timedelta(days=10):
        warning_limit = (lifetime / 2).total_seconds()
    elif lifetime < timedelta(days=90):
        warning_limit = (lifetime / 3).total_seconds()
    else:
        warning_limit = 2629743

    delta = (not_after - datetime.now(tz=timezone.utc)).total_seconds()
    if delta < 0:
        text = click.style("Expired!", fg="red")
    elif delta < warning_limit:
        text = click.style("Expires soon!", fg="yellow")
    else:
        text = click.style("Valid", fg="green")

    return f"{get_local_datetime(not_after)} ({text})"


def get_hash_algorithm_name(cert: Certificate) -> str | None:
    return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None


def name_matches_destination(
    name: GeneralName, destination: str | IPv4Address | IPv6Address
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
    destination: str | IPv4Address | IPv6Address,
    last_cert: Certificate | None,
) -> Certificate:
    sans: list[str] = []
    scts: list[SignedCertificateTimestamp] = []
    policies: list[PolicyInformation] = []
    ekus: list[str] = []
    is_ca = False

    for ext in cert.extensions:
        if ext.oid.dotted_string == "2.5.29.17":
            for name in ext.value:
                if last_cert is None and name_matches_destination(name, destination):
                    sans.append(click.style(str(name.value), fg="green"))
                else:
                    sans.append(str(name.value))
        elif ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.2":
            scts.extend(ext.value)
        elif ext.oid.dotted_string == "2.5.29.32":
            policies = ext.value
        elif ext.oid.dotted_string == "2.5.29.37":
            ekus = [eku._name for eku in ext.value]
        elif isinstance(ext.value, BasicConstraints):
            is_ca = ext.value.ca

    click.secho("#############################################################")

    print_field("Subject", [cert.subject.rfc4514_string()])
    print_field("Issuer", [cert.issuer.rfc4514_string()])
    print_field("Serial", [cert.serial_number])
    print_field("Key type", [get_key_info(cert.public_key())])
    print_field("Not before", [get_local_datetime(get_not_before(cert))])
    print_field("Not after", [get_not_after_status(cert)])
    print_field("SANs", sans)
    print_field("SCTs", get_log_names(scts))
    print_field("Type", [get_type(policies, is_ca=is_ca)])
    print_field("Extended Key Usages", ekus)
    print_field("Signature alg", [get_hash_algorithm_name(cert)])
    print_field("SHA1", [cert.fingerprint(hashes.SHA1()).hex()])  # noqa:S303
    print_field("SHA256", [cert.fingerprint(hashes.SHA256()).hex()])

    if cert.fingerprint(hashes.SHA256()).hex() in BAD_BUYPASS_CERTS:
        click.secho("This is a bad Buypass cert!", fg="red")

    if last_cert is not None:
        try:
            last_cert.verify_directly_issued_by(cert)
        except (ValueError, TypeError, InvalidSignature):
            click.secho("This cert is not the issuer of the previous cert", fg="red")

    if cert.issuer == cert.subject:
        click.secho("Self signed cert!", fg="red")

    click.echo()
    return cert


if __name__ == "__main__":
    main()
