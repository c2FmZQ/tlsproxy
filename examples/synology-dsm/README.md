# TLSPROXY on Synology DSM

Running tlsproxy on [Synology DSM](https://www.synology.com/en-us/dsm) is pretty straight forward using Container Manager.

## Create a tlsproxy user and a tlsproxy group

* Go to: `Control Panel` -> `User & Group`
* In the `User` tab, click `Create` to create the tlsproxy user.
* In the `Group` tab, click `Create` to create the tlsproxy group. Assign the tlsproxy user to the new group.

Then determine the tlsproxy UID and GID. The simplest way is to ssh into the DSM and run:

```
# id tlsproxy
uid=1031(tlsproxy) gid=100(users) groups=100(users),65537(tlsproxy)
    ^^^^                                            ^^^^^
```

## Create the tlsproxy project directory

* Go to: `File Station`
* Create a new directory somewhere and make it accessible to user tlsproxy.
* Create a subdirectory named `config` and save your `config.yaml` file there. Make sure they are readable by user tlsproxy.

## Create the container manager project

* Go to: `Container Manager` -> `Project`
* Click `Create`
* Enter `tlsproxy` as project name.
* Select the directory that was created earlier as path.
* Enter the following compose.yaml, replacing UID, GUI, and PASSPHRASE:

```yaml
services:
  tlsproxy:
    container_name: tlsproxy
    image: c2fmzq/tlsproxy:latest
    restart: always
    # tlsproxy:tlsproxy
    user: UID:GUI   <--- update this
    environment:
      - TLSPROXY_PASSPHRASE=PASSPHRASE   <--- and this
    volumes:
      - ./cache:/.cache
      - ./config:/config:ro
    network_mode: host
```

Start the project and make sure the container is running. The log should show:

```
INF Accepting TLS connections on [::]:10443
```

## Update your firewall rules

* Forward ports 80 and 443 to the DSM's IP address and ports 10080 and 10443, respectively.

At this point, incoming traffic should be directed to tlsproxy.

