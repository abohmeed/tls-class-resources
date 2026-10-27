# SSL/TLS Essentials: class resources

Lab files for the Udemy course **SSL/TLS Essentials** (2026 edition).

Lab baseline: Ubuntu 26.04 LTS (OpenSSL 3.5, nginx 1.28, Apache 2.4, Tomcat 10.1 on OpenJDK 25).

| Folder | What is in it |
|---|---|
| Section 04 | HTTPS server configs for Nginx, Apache and Tomcat, following Mozilla's intermediate TLS profile |
| Section 05 | Your own CA: root and intermediate CA configs, server and client request configs, an mTLS Nginx config, and build-ca.sh, which builds and checks the whole chain |

More sections are added as their lessons are published.

## Build the CA from Section 05

```bash
cd "Section 05"
sudo CA_PASS='a-lab-only-passphrase' ./build-ca.sh
```

The script creates the CA under /root/tls-ca (override with BASE=...), issues a server and a client certificate, revokes one, publishes CRLs and tests mutual TLS. It stops at the first failed check.

These files are for a lab. Never reuse the lab CA, its keys or its passphrase for anything real.
