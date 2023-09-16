# TLSCLIENT

The tlsproxy command establishes a TLS connection with a TLS server and redirects the stream to its stdin and stdout.

It is particularly useful as proxy command with openssh connecting to sshd behind tlsproxy.

Example:

Configure a backend in tlsproxy with:

```yaml
backends:
- serverNames:
  - ssh.example.com
  mode: tcp
  addresses:
  - 192.168.1.10:22
  alpnProtos:
  - ssh
```

Then, in .ssh/config:

```
Host ssh.example.com
  ProxyCommand /path/to/tlsclient -alpn=ssh %h:443
```

Then run:
```console
ssh user@ssh.example.com
```
