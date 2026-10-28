# SSL/TLS Essentials: class resources

Lab files for the Udemy course **SSL/TLS Essentials** (2026 edition).

Lab baseline: Ubuntu 26.04 LTS (OpenSSL 3.5, nginx 1.28, Apache 2.4, Tomcat 10.1 on OpenJDK 25).

| Folder | What is in it |
|---|---|
| Section 01 | The lab container: a Dockerfile that runs Ubuntu 26.04's OpenSSL 3.5 on any OS, and tls-lab.sh, a shell alias for it |
| Section 04 | HTTPS server configs for Nginx, Apache and Tomcat, following Mozilla's intermediate TLS profile |
| Section 05 | Your own CA: root and intermediate CA configs, server and client request configs, an mTLS Nginx config, and build-ca.sh, which builds and checks the whole chain (random serial numbers) |
| Section 07 | TLS on Kubernetes (k3s, Traefik, Gateway API, cert-manager): the Traefik HelmChartConfig, self-signed and lab-CA ClusterIssuers, Certificates, a whoami app with its HTTPRoutes, and Let's Encrypt DNS-01 and HTTP-01 issuers |

More sections are added as their lessons are published.

## The lab container from Section 01

```bash
cd "Section 01"
docker build -t tls-lab .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work tls-lab version
source tls-lab.sh        # then: tls-lab version
```

The -v mount is what makes files the container writes appear in your folder; --user makes them yours instead of root's on a Linux host. On Windows PowerShell, leave out --user and write the mount as `-v "${PWD}:/work"`.

## Build the CA from Section 05

```bash
cd "Section 05"
sudo CA_PASS='a-lab-only-passphrase' ./build-ca.sh
```

The script creates the CA under /root/tls-ca (override with BASE=...), issues a server and a client certificate, revokes one, publishes CRLs and tests mutual TLS. It stops at the first failed check.

## Section 07: the lab CA issuer

clusterissuer-lab-ca.yaml needs a Secret built from the Section 05 CA. It is never committed; create it with:

```bash
cd /root/tls-ca/intermediate
openssl pkey -in private/intermediate.key -out private/intermediate-plain.key   # asks for the CA passphrase
kubectl create secret tls lab-ca -n cert-manager --cert=certs/ca-chain.crt --key=private/intermediate-plain.key
shred -u private/intermediate-plain.key
```

Copy k3s-traefik-config.yaml (or k3s-traefik-config-tls39.yaml for TLS-39 alone) to /var/lib/rancher/k3s/server/manifests/. On k3s, do not apply the Gateway API CRDs by hand: k3s bundles them. The Let's Encrypt issuers carry a placeholder hostedZoneID; put your own zone ID in before applying them.

These files are for a lab. Never reuse the lab CA, its keys or its passphrase for anything real.
