# SSL/TLS Essentials: class resources

Lab files for the Udemy course **SSL/TLS Essentials** (2026 edition).

Lab baseline: Ubuntu 26.04 LTS (OpenSSL 3.5, nginx 1.28, Apache 2.4, Tomcat 10.1 on OpenJDK 25).

| Folder | What is in it |
|---|---|
| Section 01 | The lab container: a Dockerfile that runs Ubuntu 26.04's OpenSSL 3.5 on any OS, and tls-lab.sh, a shell alias for it |
| Section 04 | HTTPS server configs for Nginx, Apache and Tomcat, following Mozilla's intermediate TLS profile |
| Section 05 | Your own CA: root and intermediate CA configs, server and client request configs, an mTLS Nginx config, and build-ca.sh, which builds and checks the whole chain (random serial numbers) |
| Section 07 | TLS on Kubernetes (a kind cluster, Traefik, Gateway API, cert-manager): the kind config, Traefik Helm values, self-signed and lab-CA ClusterIssuers, Certificates, a whoami app with its HTTPRoutes, Let's Encrypt DNS-01 (Route 53) and HTTP-01 issuers, and the IAM policy for cert-manager. The k3s-*.yaml files are the same Traefik settings as a k3s HelmChartConfig |
| Section 09 | Troubleshooting: make-broken-certs.sh, which builds a throwaway CA and five broken certificates in the current folder (TLS-44), and tls-capture-dsb.pcapng, a short HTTPS capture with its TLS secrets inside, which opens decrypted in Wireshark 3.0 or later (TLS-45) |

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

## Section 07: the cluster and the lab CA issuer

```bash
cd "Section 07"
kind create cluster --name tls --config kind-config.yaml        # HTTP on 127.0.0.1:30080, HTTPS on 127.0.0.1:30443
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/standard-install.yaml
helm install traefik oci://ghcr.io/traefik/helm/traefik --version 42.1.3 -n kube-system -f traefik-values-tls39.yaml
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --version v1.21.3 -n cert-manager --create-namespace \
  --set crds.enabled=true --set config.gatewayAPI.enabled=true --wait
```

clusterissuer-lab-ca.yaml needs a Secret built from the Section 05 CA. It is never committed; create it with:

```bash
sudo cp /root/tls-ca/intermediate/certs/ca-chain.crt /root/tls-ca/root/certs/root.crt .
sudo install -o "$USER" -m 600 /root/tls-ca/intermediate/private/intermediate.key .
openssl pkey -in intermediate.key | kubectl create secret tls lab-ca -n cert-manager --cert=ca-chain.crt --key=/dev/stdin   # asks for the CA passphrase
shred -u intermediate.key
```

The decrypted key goes through the pipe and never reaches the disk. On k3s, copy k3s-traefik-config.yaml (or k3s-traefik-config-tls39.yaml) to /var/lib/rancher/k3s/server/manifests/ instead of installing Traefik, and do not apply the Gateway API CRDs by hand: k3s bundles them. The Let's Encrypt issuers and route53-cert-manager-policy.json carry a placeholder hosted zone ID; put your own zone ID in before using them.

These files are for a lab. Never reuse the lab CA, its keys or its passphrase for anything real.

## Where to go next (TLS-47)

Where changes are announced:
- CA/Browser Forum ballots (the rules for public certificates, such as SC-081 on lifetimes): https://cabforum.org/ballots/
- Let's Encrypt blog: https://letsencrypt.org/blog/
- Certbot changelog: https://github.com/certbot/certbot/blob/main/certbot/CHANGELOG.md
- cert-manager releases: https://cert-manager.io/docs/releases/

Tools to keep:
- TLSRef Configurator (formerly Mozilla's SSL Configuration Generator): https://configurator.tlsref.org/
- testssl.sh (on Ubuntu, the package testssl.sh installs the command testssl): https://testssl.sh/
- crt.sh, search Certificate Transparency logs: https://crt.sh/
- openssl s_client: https://docs.openssl.org/3.5/man1/openssl-s_client/

Standards behind the course:
- TLS 1.3: RFC 9846 (July 2026, replaces RFC 8446): https://www.rfc-editor.org/rfc/rfc9846.html
- X.509 certificates and CRLs: RFC 5280: https://www.rfc-editor.org/rfc/rfc5280.html
- ACME: RFC 8555: https://www.rfc-editor.org/rfc/rfc8555.html
- ACME Renewal Information (ARI): RFC 9773: https://www.rfc-editor.org/rfc/rfc9773.html
