#!/usr/bin/env python3

from datetime import datetime, timedelta
from sys import argv
from cryptography.x509.base import random_serial_number
from flask import Flask, request, send_file
from os import getenv
from dotenv import load_dotenv
from pathlib import Path
from OpenSSL import crypto, SSL

load_dotenv()

CERTS_LOCATION = getenv("CERTS_LOCATION")

CA_CN=getenv("CA_CN")
CA_COUNTRY = getenv("CA_COUNTRY")
CA_STATE = getenv("CA_STATE")
CA_CITY = getenv("CA_CITY")
CA_ORG = getenv("CA_ORG")
CA_EMAIL = getenv("CA_EMAIL")


app = Flask(__name__)

def gen_ca_cert(key):
    utcnow = datetime.utcnow()
    now = str.encode(utcnow.strftime("%Y%m%d%H%M%SZ"))
    expire = str.encode((utcnow + timedelta(days=365)).strftime("%Y%m%d%H%M%SZ"))

    crt = crypto.X509()
    crt.set_version(2)
    crt.set_serial_number(random_serial_number())
    crt.set_notBefore(now)
    crt.set_notAfter(expire)

    subject = crt.get_subject()
    subject.commonName = CA_CN
    subject.countryName = CA_COUNTRY
    subject.emailAddress = CA_EMAIL
    subject.stateOrProvinceName = CA_STATE
    subject.localityName = CA_CITY
    subject.organizationName = CA_ORG

    crt.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=crt),
    ])

    crt.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=crt),
    ])

    crt.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
    ])

    crt.set_issuer(subject)
    crt.set_pubkey(key)
    crt.sign(key, 'sha256')

    return crt


def gen_private_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    
    return key


def gen_cert_request(domain, subdomains, key):
    csr = crypto.X509Req()
    csr.get_subject().commonName = domain
    csr.get_subject().countryName = CA_COUNTRY
    csr.get_subject().emailAddress = CA_EMAIL
    csr.get_subject().stateOrProvinceName = CA_STATE
    csr.get_subject().localityName = CA_CITY
    csr.get_subject().organizationName = CA_ORG

    # X509 Extensions
    base_constraints = [
        crypto.X509Extension(
            b"keyUsage",
            False,
            b"Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment",
        ),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ]
    x509_extensions = base_constraints
    ss = [f"DNS: {domain}"]
    for subdomain in subdomains:
        ss.append(f"DNS: {subdomain}.{domain}")
    ss = str.encode(", ".join(ss))
    san_constraint = crypto.X509Extension(b"subjectAltName", False, ss)
    x509_extensions.append(san_constraint)

    csr.add_extensions(x509_extensions)

    csr.set_pubkey(key)
    csr.sign(key, "sha256")

    return csr


def ca_sign_csr(csr):
    utcnow = datetime.utcnow()
    now = str.encode(utcnow.strftime("%Y%m%d%H%M%SZ"))
    expire = str.encode((utcnow + timedelta(days=365)).strftime("%Y%m%d%H%M%SZ"))

    crt = crypto.X509()
    crt.set_version(2)
    crt.set_serial_number(random_serial_number())
    crt.set_notBefore(now)
    crt.set_notAfter(expire)
    crt.set_issuer(CA_CERT.get_subject())
    crt.set_subject(csr.get_subject())
    crt.set_pubkey(csr.get_pubkey())
    crt.add_extensions(csr.get_extensions())

    crt.sign(CA_KEY, "sha256")
    return crt


@app.route("/<domain>/<tld>")
def gen_cert(domain, tld):
    subdomains = ",".join([*request.args])
    subdomains_dir = "+".join([*request.args])
    path = Path(f"{CERTS_LOCATION}/{tld}/{domain}/{subdomains_dir}")
    if path.exists():
        if [*request.args]:
            if len([*request.args]) == 1:
                return f"Certificate for {subdomains}.{domain}.{tld} already exists"
            return f"Certificate for {{{subdomains}}}.{domain}.{tld} already exists"
        return f"Certificate for {domain}.{tld} already exists"

    key = gen_private_key()
    csr = gen_cert_request(f"{domain}.{tld}", [*request.args], key)
    crt = ca_sign_csr(csr)

    path.mkdir(parents=True)
    (path / f"{domain}.{tld}.key").write_bytes(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    )
    (path / f"{domain}.{tld}.crt").write_bytes(
        crypto.dump_certificate(crypto.FILETYPE_PEM, crt)
    )

    if [*request.args]:
        if len([*request.args]) == 1:
            return f"Generate certificate for {subdomains}.{domain}.{tld}"
        return f"Generate certificate for {{{subdomains}}}.{domain}.{tld}"
    return f"Generate certificate for {domain}.{tld}"


@app.route("/get/crt/<domain>/<tld>")
def get_cert(domain, tld):
    subdomains = "+".join([*request.args])
    path = Path(f"{CERTS_LOCATION}/{tld}/{domain}/{subdomains}")
    if not path.exists():
        return "Key not found"
    path = path / f"{domain}.{tld}.crt"
    return send_file(path, mimetype="text/plain")


@app.route("/get/key/<domain>/<tld>")
def get_key(domain, tld):
    subdomains = "+".join([*request.args])
    path = Path(f"{CERTS_LOCATION}/{tld}/{domain}/{subdomains}")
    if not path.exists():
        return "Key not found"
    path = path / f"{domain}.{tld}.key"
    return send_file(path, mimetype="text/plain")
    
def run():
    app.run(host="127.0.0.1", port=5000)

def gen():
    CA_CERT=getenv("CA_CERT")
    CA_KEY=getenv("CA_KEY")

    key = gen_private_key()
    crt = gen_ca_cert(key)

    key_path = Path(CA_KEY)
    crt_path = Path(CA_CERT)
    
    crt_path.parent.mkdir(exist_ok=True, parents=True)
    crt_path.parent.mkdir(exist_ok=True, parents=True)
    
    key_path.write_bytes(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    )
    crt_path.write_bytes(
        crypto.dump_certificate(crypto.FILETYPE_PEM, crt)
    )

if argv[1] == "gen":
    gen()
    exit(0)

CA_CERT = crypto.load_certificate(
    crypto.FILETYPE_PEM, open(getenv("CA_CERT"), "rt").read()
)
CA_KEY = crypto.load_privatekey(
    crypto.FILETYPE_PEM, open(getenv("CA_KEY"), "rt").read()
)

run()