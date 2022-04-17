# Certificate Generator Server

Generate TLS certificates signed by a your own CA for local HTTPS development from a simple API  
This is not a secure server, this should ONLY run on your machine, as anyone with access to the API
can access the generated certificates private keys

* `/<domain>/<tld>?<subdomain1>&<subdomain2>&<subdomain3>...` to generate the certificate
* `/get/crt/<domain>/<tld>?<subdomain1>&<subdomain2>&<subdomain3>...` to get the PEM format certificate
* `/get/key/<domain>/<tld>?<subdomain1>&<subdomain2>&<subdomain3>...` to get the PEM format private key

## Getting started
Rename or copy `.env.example` to `.env` and change the fields to your values

Generate your CA certificate with `python3 app.py gen` or copy your certificate and key to the location specified in `.env`

Launch the server with `python3 app.py`
