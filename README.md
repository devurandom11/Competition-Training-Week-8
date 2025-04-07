# Deploying a Virtual Network with Router, DMZ, and Servers – Step-by-Step Workshop

## Overview and Objectives

In this workshop, we will build a virtual network environment with four Linux VMs acting in different roles on separate subnets (LAN and DMZ) behind a router/firewall. We'll configure networking and services step-by-step, including firewall rules and security hardening. By the end, you will have:

*   Alpine Linux as a router (firewall) providing WAN internet access to two internal networks (LAN and DMZ) via NAT.
*   CentOS as a web server in the DMZ running a LAMP stack (Linux, Apache, MariaDB, PHP) with Nginx as a reverse proxy in front of Apache, and SELinux in enforcing mode to illustrate policy enforcement.
*   Arch Linux as a file server in the LAN running vsftpd (FTP server) and Samba (SMB file sharing), accessible only from the LAN.
*   Ubuntu Desktop as a jump-box in the LAN, which will be used to access the other servers (e.g. SSH into them, browse the web service, test FTP/SMB, etc.). This simulates an admin workstation that has access to both networks.

### Network segments

The Alpine router will separate three networks (one WAN, plus two internal networks). The LAN subnet will be `192.168.10.0/24` (trusted internal network) and the DMZ subnet will be `10.10.10.0/24` (perimeter network for public-facing server). The router's firewall will be configured so that external (WAN) traffic can reach the DMZ web server (on specific ports) but not the LAN, and the LAN can reach the DMZ (for example, the jump-box can reach the web server), while the DMZ cannot initiate connections into the LAN. The Arch file server will be restricted to only communicate within the LAN and not with the DMZ, whereas the Ubuntu jump-box will be allowed to access the DMZ. All internet-bound traffic from LAN/DMZ will go through the Alpine router (which performs NAT).

## Network Topology


*   **Alpine Linux Router** – three network interfaces:
    *   `eth0` (WAN) – Connected to the external network/Internet. (Use DHCP or a static IP from your upstream router. For example, assume it gets an IP `192.0.2.100` from an upstream NAT for testing Internet access.)
    *   `eth1` (DMZ) – Static IP `10.10.10.1/24` (acts as default gateway for the DMZ network).
    *   `eth2` (LAN) – Static IP `192.168.10.1/24` (acts as default gateway for the LAN network).

*   **CentOS Web Server (DMZ)** – one interface on DMZ network:
    *   `eth0` – Static IP `10.10.10.10/24`, gateway `10.10.10.1` (Alpine router DMZ IP). DNS can be set to a public DNS (e.g., `8.8.8.8`) if needed for internet access.

*   **Arch Linux File Server (LAN)** – one interface on LAN network:
    *   `eth0` – Static IP `192.168.10.10/24`. For added security, we will not set a default gateway on this server (so it has no direct route to Internet or DMZ via the router). It will still be reachable from LAN, but it won't initiate external connections. (If a gateway is required for updates, you can temporarily add `192.168.10.1`.)

*   **Ubuntu Desktop Jump Box (LAN)** – one interface on LAN network:
    *   `eth0` – Static IP `192.168.10.50/24`, gateway `192.168.10.1`. DNS can be set to the router or public DNS. This box will be used to reach both the DMZ (e.g. SSH/Web to CentOS) and the LAN (e.g. RDP/SSH to Arch or router).

Make sure each VM is connected to the proper virtual network/switch corresponding to these subnets. (For example, in your hypervisor, Alpine's `eth1` and CentOS's `eth0` are connected to a "DMZ" switch, Alpine's `eth2`, Arch's `eth0`, and Ubuntu's `eth0` to a "LAN" switch, etc.)

## 1. Alpine Linux Router Setup (Routing & Firewall)

The Alpine Linux router will perform IP forwarding, network address translation (NAT) for internet access, and filtering between LAN and DMZ. We will enable IP forwarding, set up the network interfaces with static IPs, and configure firewall (`iptables`) rules.

### 1.1 Configure Alpine Network Interfaces

Log into the Alpine router VM console. Alpine typically uses the `/etc/network/interfaces` file with `ifupdown`. You can use Alpine's setup script or edit the config manually:

*   Run the Alpine setup script for networking: `setup-interfaces` (if available) and assign:
    *   `eth0` to use DHCP (if your lab provides a WAN via DHCP) or a static external IP.
    *   `eth1` static IP `10.10.10.1/24` (no DHCP on DMZ in this guide).
    *   `eth2` static IP `192.168.10.1/24`.
    *   When prompted for default gateway, set it for the WAN (`eth0`) if needed (e.g., the upstream router IP).
    *   DNS can be a public server (e.g., `8.8.8.8`).

Alternatively, manually edit `/etc/network/interfaces` to include entries for `eth1` and `eth2` with the above static IPs, then bring them up with `ifup eth1 && ifup eth2`. Verify you can ping CentOS from Alpine (after CentOS is configured) on `10.10.10.10` and the Ubuntu jump-box on `192.168.10.50` once everything is up.

### 1.2 Enable IP Forwarding and NAT

By default, Alpine (and Linux in general) does not forward IP packets between interfaces until enabled. Do the following on Alpine as root:

```bash
# Enable IPv4 forwarding in the kernel (this persists in /etc/sysctl.conf)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p  # apply the sysctl settings immediately
```

Now install and initialize the `iptables` service (Alpine is minimal, so it may not be installed by default):

```bash
sudo apk add iptables           # install iptables firewall utilities
sudo rc-update add iptables     # enable iptables service at boot
```

Next, add firewall rules for NAT and forwarding. We will set up a basic firewall that implements our policy:

*   **NAT (Masquerading):** All traffic from LAN or DMZ going out via Alpine's `eth0` (WAN) will have its source IP masqueraded as Alpine's WAN IP for internet access.
*   **WAN → DMZ (Port Forwarding):** We will allow outside access to the CentOS web server on HTTP (and HTTPS) by forwarding those ports to the DMZ host.
*   **LAN ↔ DMZ:** Allow LAN to initiate connections to DMZ, but block DMZ from initiating into LAN. Additionally block the Arch file server specifically from reaching the DMZ (as an extra precaution).
*   **LAN/DMZ → WAN:** Allow LAN and DMZ to access the Internet (outbound), but unsolicited inbound from WAN is blocked except the forwarded web ports.
*   **Basic sanity rules:** Allow established/related connections, drop invalid packets, etc.

We will use `iptables` commands to implement this. Run the following on Alpine's shell (the `eth0`, `eth1`, `eth2` naming assumes as defined above):

```bash
# Flush any existing rules (optional, to start fresh)
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X

# Default drop on forwarding chain for security
sudo iptables -P FORWARD DROP

# 1) Allow established/related traffic to pass back (for TCP handshakes, etc.)
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2) Block Arch file server from initiating to DMZ (Arch IP = 192.168.10.10)
sudo iptables -A FORWARD -i eth2 -s 192.168.10.10/32 -d 10.10.10.0/24 -j DROP

# 3) Allow LAN to DMZ (other LAN hosts can reach DMZ) and LAN to WAN
sudo iptables -A FORWARD -i eth2 -s 192.168.10.0/24 -o eth1 -d 10.10.10.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -i eth2 -s 192.168.10.0/24 -o eth0 -m conntrack --ctstate NEW -j ACCEPT

# 4) Allow DMZ to WAN (e.g., DMZ server can reach Internet for updates)
sudo iptables -A FORWARD -i eth1 -s 10.10.10.0/24 -o eth0 -m conntrack --ctstate NEW -j ACCEPT

# 5) Block DMZ to LAN (prevent any DMZ host from initiating into LAN)
sudo iptables -A FORWARD -i eth1 -s 10.10.10.0/24 -o eth2 -d 192.168.10.0/24 -j DROP

# 6) Port forward: WAN 80/443 → DMZ web server (10.10.10.10)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80  -j DNAT --to-destination 10.10.10.10:80  # HTTP
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 10.10.10.10:443 # HTTPS
sudo iptables -A FORWARD -i eth0 -p tcp --dport 80  -d 10.10.10.10 -m conntrack --ctstate NEW -j ACCEPT  # allow forwarded traffic
sudo iptables -A FORWARD -i eth0 -p tcp --dport 443 -d 10.10.10.10 -m conntrack --ctstate NEW -j ACCEPT

# 7) Enable NAT (masquerade) for LAN and DMZ subnets going out via eth0 (WAN)
sudo iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o eth0 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24   -o eth0 -j MASQUERADE

# (Optional) Allow router itself to be pinged or reached from LAN:
sudo iptables -A INPUT -i eth2 -s 192.168.10.0/24 -m conntrack --ctstate NEW -j ACCEPT
# (Optional) Allow SSH to router from LAN (for management):
sudo iptables -A INPUT -i eth2 -s 192.168.10.0/24 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# Drop other inbound traffic to router
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
sudo iptables -A INPUT -p icmp -j ACCEPT   # allow ping for testing
sudo iptables -A INPUT -p tcp --syn -j DROP
```

**Explanation of the above rules:** We set the default policy to `DROP` for forwarding (everything is denied unless whitelisted). We allow established connections to pass (so returning packets in a session are not blocked). We explicitly drop any attempt by the Arch file server (`192.168.10.10`) to go to the DMZ network. We then allow any new connections from the LAN (`192.168.10.0/24`) to the DMZ network and to the WAN. We allow the DMZ network to initiate connections out to WAN (internet). We block any new connection from DMZ to LAN. We forward incoming WAN HTTP/HTTPS to the web server in DMZ (`10.10.10.10`). Finally, we enable NAT masquerading on WAN for both subnets, so that LAN and DMZ hosts can reach the internet with their source IP translated to the router's WAN IP. (The optional `INPUT` rules allow managing the router from the LAN – adjust as needed.)

After entering these rules, save them so they persist on reboot:

```bash
sudo /etc/init.d/iptables save    # Save the current iptables rules to /etc/iptables/rules
```

Alpine's `iptables` service (enabled earlier) will load these saved rules on boot. You can verify by listing the rules: `sudo iptables -L -v && sudo iptables -t nat -L -v`.

### Testing the Router & Firewall

At this stage, test basic connectivity (after other VMs are configured too):

*   From Alpine, try to ping an internet host (e.g., `ping -c 4 8.8.8.8`) to ensure WAN is working.
*   From Ubuntu jump-box (`192.168.10.50`), ping the CentOS server (`10.10.10.10`) – this should succeed (LAN to DMZ allowed).
*   From CentOS (`10.10.10.10`), ping the Arch server (`192.168.10.10`) – this should fail (DMZ to LAN blocked).
*   From Arch (`192.168.10.10`), ping the CentOS server (`10.10.10.10`) – this should fail (we dropped Arch->DMZ). The Arch server should only communicate with LAN (and it has no gateway set, so it wouldn't know how to reach `10.10.10.0/24` anyway).
*   From Ubuntu, try pinging Arch (`192.168.10.10`) – should succeed (LAN to LAN).
*   If you set up SSH on CentOS, try `ssh` from Ubuntu to CentOS (should work). Try `ssh` from CentOS to Ubuntu (should fail, DMZ->LAN).
*   Once the web server is up, from Ubuntu you should be able to open a browser to `http://10.10.10.10` (or to the Alpine's WAN IP `http://192.0.2.100` if you set port forwarding and have an external test access).
*   From outside (simulate by using the host or another external VM), try to access the WAN IP on port 80 – it should be forwarded to the web server's site.

These tests confirm the firewall segmentation is working as intended.

## 2. CentOS DMZ Web Server Setup (LAMP Stack with Nginx Reverse Proxy)

Next, set up the CentOS VM as a web server on the DMZ network. This server will run a classic LAMP stack (Apache, PHP, MariaDB) and we will put Nginx in front of Apache as a reverse proxy. We will also ensure SELinux remains in enforcing mode and configure it to allow our web setup to function (demonstrating SELinux policy enforcement).

### 2.1 CentOS Basic Setup and Package Installation

*   **Network Config:** Ensure the CentOS VM's network interface is on the DMZ switch and has the static IP `10.10.10.10/24`, gateway `10.10.10.1`. On CentOS, edit `/etc/sysconfig/network-scripts/ifcfg-eth0` accordingly or use `nmtui` for convenience. After configuring, test connectivity: you should ping the router (`10.10.10.1`) and the Ubuntu host (via router) once firewall is open. Also ensure DNS is set (e.g., in `/etc/resolv.conf`).
*   **Update System:** It's good practice to update packages first:
    ```bash
    sudo yum update -y    # (Use dnf if CentOS 8+, accordingly)
    ```
*   **Install LAMP components:**
    ```bash
    sudo yum install -y httpd php php-mysqlnd mariadb-server
    ```
    This installs Apache HTTPd, PHP, and MariaDB (MySQL) server on CentOS. Enable and start these services:
    ```bash
    sudo systemctl enable httpd mariadb
    sudo systemctl start httpd mariadb
    ```
    Confirm Apache is running (e.g., `systemctl status httpd`). You can also open a browser on the Ubuntu jump-box to `http://10.10.10.10` – you should see the Apache default test page.
*   **Secure MariaDB:** (Optional but recommended) run `sudo mysql_secure_installation` to set a root DB password and remove test DB/users as prompted.
*   **Test PHP:** Create a test PHP page to ensure PHP is working. For example:
    ```bash
    echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php
    ```
    In a browser (from Ubuntu or elsewhere with access), visit `http://10.10.10.10/info.php`. You should see the PHP info page. Remove it afterwards for security (`rm /var/www/html/info.php`).

At this point, we have a basic working Apache+PHP (and database ready). Now we'll set up Nginx as a reverse proxy in front of Apache.

### 2.2 Install and Configure Nginx Reverse Proxy

*   **Install Nginx:**
    ```bash
    sudo yum install -y nginx
    sudo systemctl enable nginx
    ```
*   **Configure Nginx:** We want Nginx to listen on port 80 (and 443 for HTTPS if needed) and forward requests to Apache (which we will move to a different port). By default, Apache is listening on 80, which conflicts with Nginx. We have two options:
    1.  Change Apache to listen on another port (e.g., 8080) and have Nginx proxy to `localhost:8080`.
    2.  Or configure Nginx to listen on port 80 for incoming requests and proxy to Apache's UNIX socket or port 81.

    We'll use option 1 for simplicity.
*   **Reconfigure Apache to port 8080:** Open `/etc/httpd/conf/httpd.conf` and find the line `Listen 80`. Change it to `Listen 127.0.0.1:8080` (we'll bind Apache to localhost on port 8080). Also update any `VirtualHost` in `/etc/httpd/conf.d/` to port 8080 if present (e.g., in `welcome.conf` or others). Then restart Apache:
    ```bash
    sudo systemctl restart httpd
    ```
    Verify Apache is now listening on `127.0.0.1:8080` (use `ss -tlnp | grep httpd`).
*   **Configure Nginx site:** Create an Nginx config file for the site, e.g., `/etc/nginx/conf.d/reverse-proxy.conf`:
    ```nginx
    server {
        listen       80;
        server_name  _;  # catch all

        access_log  /var/log/nginx/access.log  main;
        error_log   /var/log/nginx/error.log warn;

        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    ```
    This configuration tells Nginx to listen on port 80 and forward all requests to the Apache backend on `localhost:8080`. It also passes along the original host and IP info to Apache via headers.
*   **Start Nginx:**
    ```bash
    sudo systemctl start nginx
    ```
    Now Nginx should be listening on `10.10.10.10:80`. If you visit the web server from the jump-box browser, you should still see the Apache test page, but it's now coming through Nginx. Nginx is effectively acting as a reverse proxy in front of Apache.

### 2.3 SELinux Configuration for Reverse Proxy

CentOS comes with SELinux enabled (enforcing) by default, which is a good thing for security. We keep SELinux in enforcing to demonstrate policy enforcement, but we need to adjust it to allow our custom configuration (Nginx->Apache proxy).

By default, SELinux HTTP policy expects web servers to run on standard ports (80, 443). We changed Apache to listen on 8080, and we have Nginx (running as an HTTP daemon) trying to connect to `localhost:8080`. Out-of-the-box, SELinux will prevent Nginx from connecting to Apache on port 8080 because that's considered an unallowed network connection. (SELinux confines the Nginx process in the `httpd_t` domain which by default cannot initiate outbound connections to arbitrary ports.) If we check `/var/log/audit/audit.log` after trying to load the site, we would likely see a denied message.

To fix this, we have a couple of options:

1.  Allow the web daemon to make network connections in general.
2.  Or specifically label port 8080 as an HTTP port.

The simpler approach for a workshop is to enable the SELinux boolean that permits HTTP network connections. There is a boolean `httpd_can_network_connect` which, when ON, allows processes in the `httpd_t` domain (like Apache or Nginx) to initiate network connections. There's also a more specific `httpd_can_network_relay` for reverse proxy usage, but enabling the general network connect will cover it.

Run the following on CentOS to update SELinux policy on the fly:

```bash
sudo setsebool -P httpd_can_network_connect on
```

This sets the boolean persistently (`-P`). Now Nginx is allowed to connect to Apache's 8080 port, and SELinux will no longer block it. (Alternatively, we could have added port 8080 to the `http_port_t` context via `semanage port -a -t http_port_t -p tcp 8080`, which is another valid solution. But using the boolean is quick for our case.)

*   **Note:** We did not disable SELinux at any point – we adjusted it. This demonstrates how SELinux provides a secure default (it "prevents NGINX from accessing port 8888 or any other non-standard port" in a reverse proxy scenario) and how we can selectively enable needed access. You can check SELinux status with `sestatus` (it should show "Current mode: enforcing"). The site should now work via Nginx with SELinux enforcing. If you had an SELinux denial before, you can verify it's gone by retrying access and checking `audit.log` again.

### 2.4 Deploy a Sample PHP Website

For demonstration, let's set up a simple PHP page served through Apache (and thus via Nginx). Create `/var/www/html/index.php` with a basic script. For example:

```php
<?php
  echo "<h1>Welcome to the DMZ Web Server</h1>";
  echo "<p>This is served by Apache PHP backend through Nginx reverse proxy.</p>";
?>
```

Ensure ownership is `apache:apache` (or appropriate) for the file. Navigate to `http://10.10.10.10/` from the Ubuntu jump-box browser – you should see the welcome message. This confirms PHP is working behind the proxy. (Nginx is just passing the request to Apache, which executes PHP and returns the output.)

### 2.5 Firewalld (if applicable)

If CentOS has `firewalld` enabled by default, you might need to adjust it to allow HTTP/HTTPS. Since our Alpine router already controls external access, you could even disable `firewalld` on CentOS or open the ports on the CentOS VM for LAN access. For simplicity, you can run: `sudo systemctl disable --now firewalld` on the CentOS VM (the Alpine firewall is primary here).

The CentOS web server in the DMZ is now fully set up with LAMP, behind Nginx, and SELinux is actively protecting it (try switching SELinux to permissive mode with `setenforce 0` and see that nothing is being blocked, then back to 1 – we prefer to keep it enforcing).

## 3. Arch Linux LAN File Server Setup (FTP and Samba)

Now we configure the Arch Linux VM as an internal file server, providing FTP and SMB file sharing services. This server is on the LAN and should only be accessible from the LAN. We will set up `vsftpd` and `Samba`, and also show how to restrict these services to the LAN network.

### 3.1 Arch Linux Basic Config

Ensure the Arch VM is connected to the LAN and has IP `192.168.10.10/24` (with no gateway set, as discussed). Update the system (`sudo pacman -Syu`) if needed.

### 3.2 Install and Configure FTP (vsftpd)

*   **Install vsftpd:**
    ```bash
    sudo pacman -S vsftpd
    ```
*   **Enable and start the service:**
    ```bash
    sudo systemctl enable vsftpd
    sudo systemctl start vsftpd
    ```
*   **Configure vsftpd:** Open `/etc/vsftpd.conf` in an editor. We will set it up to allow local user logins and optionally anonymous read (depending on needs). Key settings to configure:
    *   `local_enable=YES` – allows local Unix users to login via FTP.
    *   `write_enable=YES` – allows mutation (uploads, deletions) – without this, all FTP sessions are read-only.
    *   `chroot_local_user=YES` – jail local users in their home directory after login (for security).
    *   (Optional) If you want an anonymous read-only share, set `anonymous_enable=YES` and specify `anon_root=/srv/ftp` with proper perms; for this workshop, we'll focus on authenticated access.
    *   You may also limit the `listen_address` to the LAN IP if needed, but since the server only has a LAN IP and the router blocks outside access, it's fine.

    After editing, save the file and restart vsftpd (`sudo systemctl restart vsftpd`).
*   **Create an FTP user:** We need a user account for FTP login (`vsftpd` will use system accounts). You can use an existing user or create a dedicated one. For example:
    ```bash
    sudo useradd -m ftpuser -s /bin/nologin   # create a user with no shell (FTP only)
    sudo passwd ftpuser                      # set a password for FTP login
    ```
    This user's home directory (e.g., `/home/ftpuser`) will be the FTP root (with chroot enabled, they won't escape above it).
*   **Test FTP from jump-box:** From the Ubuntu desktop, you can test FTP:
    *   On Linux, run: `ftp 192.168.10.10` and login with `ftpuser` and the password. Try uploading a file (`put`) or downloading (`get`) to ensure it works.
    *   Alternatively, use a GUI FTP client on Ubuntu or command-line `curl -u ftpuser ftp://192.168.10.10/`.

By enabling `local_enable=YES` and `write_enable=YES`, we allowed authenticated users to upload files. The `chroot_local_user=YES` setting locks the user into their home directory upon login (preventing navigating to other system directories), which is a good security practice for an FTP server.

### 3.3 Install and Configure Samba (SMB file sharing)

*   **Install Samba:**
    ```bash
    sudo pacman -S samba
    ```
*   **Samba Configuration File:** Copy the default example as a starting point:
    ```bash
    sudo cp /etc/samba/smb.conf.default /etc/samba/smb.conf
    ```
    Now edit `/etc/samba/smb.conf`. Under the `[global]` section, set the `workgroup` if needed (default `WORKGROUP` is usually fine, which matches Windows default). You can also set `interfaces = 192.168.10.10/24` and `bind interfaces only = yes` to make Samba listen only on the LAN interface (added security to ensure it's not listening on any unintended interface).
*   **Define a share:** For example, add at the bottom of the file:
    ```ini
    [fileshare]
    comment = Shared Files
    path = /srv/samba/share
    browseable = yes
    read only = no
    valid users = smbuser
    ```
    This defines a share named "fileshare" located at `/srv/samba/share`. It's browseable and writeable, but only accessible by the user "smbuser".
*   **Create the shared directory and user:**
    ```bash
    sudo mkdir -p /srv/samba/share
    sudo chown nobody:nobody /srv/samba/share   # or choose a group, depending on use
    ```
    For a simple setup, we'll use a single Samba user. Create a system user (if not already existing) and set a Samba password for them:
    ```bash
    sudo useradd -M smbuser -s /sbin/nologin    # create a no-login user (no home needed, using share dir)
    sudo smbpasswd -a smbuser                   # set a Samba password for smbuser
    sudo smbpasswd -e smbuser                   # enable the user (if not auto-enabled)
    ```
    Ensure the user has permission on the share path if using `valid users`. In our case, we set `nobody:nobody` on the share and didn't add `smbuser` to it – for simplicity, instead assign ownership:
    ```bash
    sudo chown smbuser /srv/samba/share
    ```
    Or adjust the `valid users` to a group that `smbuser` is part of. The goal is `smbuser` can read/write in that directory.
*   **Start Samba services:** Enable and start the SMB (and NMB) daemons:
    ```bash
    sudo systemctl enable smb nmb
    sudo systemctl start smb nmb
    ```
    Samba should now be running and serving the defined share. You can verify the config syntax with `testparm` (Samba's tool to check `smb.conf`).
*   **Test SMB access:** From the Ubuntu jump-box, install the Samba client tools:
    ```bash
    sudo apt-get install -y smbclient
    smbclient -L 192.168.10.10 -U smbuser
    ```
    Enter the password when prompted. You should see the "fileshare" listed in the output. Then try to connect:
    ```bash
    smbclient //192.168.10.10/fileshare -U smbuser
    ```
    Once in the SMB shell, use commands like `dir` to list files, and `put` to upload, `get` to download files, etc., to ensure it works. You can also mount the share on Ubuntu via GUI (Files app -> "Connect to Server" with `smb://192.168.10.10/fileshare`).

The Samba share we created requires authentication (username/password) and is only accessible to our `smbuser` account. This demonstrates a private file share. If you wanted a public share (no auth), you could set `guest ok = yes` and use the `nobody` account, but that's optional.

**Security Note:** Since this server is only in LAN, we rely on the Alpine router to block any outside or DMZ access to these services. We also configured the services to only listen or be available on the LAN interface. For additional security, you could configure firewall on Arch (with `iptables` or `ufw`) to only allow LAN source addresses, but in our scenario it's not necessary. The router's firewall already ensures, for instance, that the DMZ cannot reach the Samba or FTP ports in LAN. (Remember, we blocked DMZ->LAN entirely, and also Arch has no route to DMZ.)

## 4. Ubuntu Desktop Jump-Box Setup (Access & Testing)

The Ubuntu Desktop doesn't require complex setup – it's primarily a client and admin workstation in the LAN. Ensure it has network configured (`192.168.10.50/24`, gateway `192.168.10.1`, and Internet access through the router). You might want to install some client tools:

*   **For SSH:** `sudo apt-get install -y openssh-client` (SSH client should be installed by default; if you want to SSH into the Ubuntu box from elsewhere, install `openssh-server` and open port if needed).
*   **Browser:** Firefox/Chrome should be installed for web testing.
*   **For RDP/VNC:** (if you plan to remote into it, set up as needed, but not required here).
*   **For FTP/SMB:** We already installed `smbclient`. You can also install an FTP client or just use the command line tools as we did.

Use the Ubuntu box to test connectivity and access to all services in the network:

*   **Web Server (CentOS):** Open a browser to `http://10.10.10.10` – you should see the demo PHP page through Nginx/Apache. Try both the DMZ IP and (if you configured port forwarding) the Alpine's WAN IP. The site should load in both cases (the latter proving the port forwarding from WAN works).
*   **SSH to CentOS:** If you set up SSH on CentOS (enable with `sudo systemctl start sshd`), test `ssh 10.10.10.10` – it should connect (LAN to DMZ allowed).
*   **FTP Server (Arch):** Connect as `ftpuser` using an FTP client or `ftp 192.168.10.10` – should login and list directories. (DMZ cannot do this, only LAN.)
*   **SMB Server (Arch):** Access the Samba share. On Ubuntu, you can do in file manager `smb://192.168.10.10/fileshare`, or use `smbclient` as shown. You should be prompted for credentials and then see the shared folder. Try creating a file.
*   **Internet:** From Ubuntu, verify you can reach the Internet via Alpine (e.g., browse to a website, or `ping 8.8.8.8`). The Alpine should NAT your traffic out. Also test that the CentOS DMZ server can ping out to say `ping -c4 8.8.8.8` (should work, since we allowed DMZ->WAN).

Everything should now be functioning with correct access controls:

*   External users (simulated by any host on the WAN side) can only reach the web server (and only on the allowed ports).
*   The DMZ web server cannot initiate connections into the LAN (it's blocked by Alpine).
*   The internal jump-box (and any LAN host) can reach the DMZ services (for maintenance or usage).
*   The internal file server is invisible to the DMZ and outside; it only serves the LAN. We even prevented it from talking to the DMZ from its side.
*   SELinux is enforcing on CentOS, so if someone tried to, say, put web content in a weird location or Nginx tried to do something unusual, SELinux would intervene. We only enabled a specific policy boolean to allow the proxy connection, rather than turning SELinux off. This highlights how SELinux policies add a layer of protection – e.g., by default NGINX could not access Apache's port until we explicitly allowed it, which is a deliberate security policy.

## 5. Summary and Next Steps

In this workshop, we set up a realistic multi-tier network environment:

*   A lightweight Alpine Linux router with `iptables` providing segmentation between a LAN and DMZ, implementing a "demilitarized zone" network design. Our firewall rules ensure that outside traffic can reach the DMZ server but not the internal LAN, and internal hosts can reach the DMZ as needed. We used NAT for internet access and showed port-forwarding for public services.
*   A CentOS web server in the DMZ running a LAMP stack with an Nginx reverse proxy. We deployed a sample PHP site and configured SELinux properly rather than disabling it – demonstrating how to adjust SELinux booleans (like `httpd_can_network_connect`) to allow necessary access while keeping the system secure.
*   An Arch Linux file server in the LAN providing internal FTP and SMB services. We configured `vsftpd` and `Samba` with appropriate settings (enabling local logins, restricting write access, etc.). The file server is only accessible from the LAN – the router's firewall and the network design protect it from the DMZ or outside.
*   An Ubuntu Desktop jump-box used for testing and administration, simulating an admin's workstation that can reach into the DMZ for management and use internal services.

You can extend this setup by adding more rules (for example, logging dropped packets, or further restricting which LAN hosts can access the DMZ), setting up HTTPS with certificates on Nginx, adding intrusion detection, etc. For instance, you might only allow the Jump-box's IP to access the DMZ SSH port, while blocking other LAN IPs – this would tighten security if needed. SELinux on CentOS can be further explored (check audit logs if you, say, try to serve content from a non-standard directory and see how to label files correctly).

This step-by-step guide can be used as a workshop to practice networking and security on a virtual lab. It demonstrates fundamental concepts of network segmentation (LAN vs DMZ), firewall configuration with `iptables`, service configuration on various Linux distros, and security best practices like least privilege (SELinux, chroot, account restrictions). By following these steps, you've built a mini network that models what is used in real-world scenarios for isolating internal resources from public-facing ones, all within a virtualized environment for learning.