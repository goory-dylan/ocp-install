### OpenShift 4.4.3 vSphere Installation Guide (UPI)

---------------------------



### 1. OpenShift 4.4.3 Minimum resource requirements

| Machine       | Operating System | vCPU | RAM   | Storage |
| ------------- | ---------------- | ---- | ----- | ------- |
| Bootstrap     | RHCOS            | 4    | 16 GB | 120 GB  |
| Control plane | RHCOS            | 4    | 16 GB | 120 GB  |
| Compute       | RHCOS            | 2    | 8 GB  | 120 GB  |

- [x] OpenShift 4.3 버전의 경우에는 위와 같이 최소 자원 요구사항이 존재하며, 해당 요구사항이 준비 되어야 설치가 가능합니다.

- [x] Control plane(master)의 경우에는 반드시 3개로 구성이 되어야 하며, Cluster 정상 구성을 위해 설치 진행 시Compute 노드는 2개를(1개 이상) 기동해야 정상적으로 설치가 진행 됩니다.



### 2. 테스트 환경

| Machine   | Operating System | vCPU | RAM   | Storage | Count |
| --------- | ---------------- | ---- | ----- | ------- | ----- |
| bastion   | RHEL 7.7         | 8    | 16 GB | 300 GB  | 1     |
| bootstrap | RHCOS 4.4.3      | 8    | 16 GB | 300 GB  | 1     |
| master    | RHCOS 4.4.3      | 8    | 32 GB | 300 GB  | 3     |
| infra     | RHCOS 4.4.3      | 8    | 32 GB | 300 GB  | 2     |
| worker    | RHCOS 4.4.3      | 8    | 16 GB | 300 GB  | 2     |

- [x] 해당 가이드는 인터넷이 되는 vSphere 환경에서 OpenShift 4.4 설치 구성 테스트를 진행 하였습니다.

- [x] 인터넷이 되는 VMware(vSphere) 환경 구축에 도움이 되었으면 합니다.

- [x] 해당 가이드는 DHCP 서버를 구성 할 수 없는 사항에 대비하여 테스트를 진행 하였습니다.

  

  2-1) User-Provisioned Infrastructure  (UPI)를 위해 준비해야 하는 부분 (사전 준비)**

  - [x] Load Balancer (HAproxy)

    > Haproxy는 OCP 4.4 설치시 Load Balancer 역할을 합니다. 
    > Haproxy(Load Balancer)는 master, infra, bootstrap node 간에 통신을 할 수 있는 front and backend protocol(Upstream)을 제공함으로써 OCP 4.4 설치에 중요한 브로커 역할을 수행합니다.

  - [x] DNS 구성

    >  RHOCP 내부 DNS로 각 Node간 FQDN Resolving으로 활용하게 되며 구성을 위한 namge.conf 설정 변경, zone 파일 생성 및 DNS 서버 방화벽 오픈 작업을 수행합니다.

  

### 3. subscription 설정

>  테스트 환경에서는 따로 yum repository를 구축하지 않고, subscription manager를 사용하였습니다.



3-1) subscription 등록

```bash
$ rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

$ subscription-manager register
Registering to: subscription.rhsm.redhat.com:443/subscription
Username: ${USERNAME} 
Password: ${PASSWORD}
The system has been registered with ID: 6b924884-039f-408e-8fad-8d6b304bc2b5
The registered system name is: localhost.localdomain
```

> 등록 시 redhat customer portal ID/PWD를 입력합니다.



3-2) OpenShift 설치에 필요한 RPM 활성화	

```bash
$ subscription-manager list --available --matches '*OpenShift*' > aaa.txt

// OpenShift Subscription만 따로 뽑아서 그 중 하나를 선택하여 등록 합니다.

$ subscription-manager attach --pool=8a85f9833e1404a9013e3cddf95a0599
Successfully attached a subscription for: Employee SKU

$ subscription-manager repos --disable="*"

$  subscription-manager repos \
    --enable="rhel-7-server-rpms" \
    --enable="rhel-7-server-extras-rpms" \
    --enable="rhel-7-server-ose-4.3-rpms"

Repository 'rhel-7-server-rpms' is enabled for this system.
Repository 'rhel-7-server-extras-rpms' is enabled for this system.
Repository 'rhel-7-server-ose-4.3-rpms' is enabled for this system.		
```



### 4. Bastion 서버 Hostname 변경

4-1) hostname 변경

```bash
$ hostnamectl set-hostname bastion.ocp.test.com
```

4-2) 변경된 hostname 확인

```bash
[root@bastion ~]# hostnamectl
   Static hostname: bastion.ocp.test.com
         Icon name: computer-vm
           Chassis: vm
        Machine ID: df1374b4f6984c949c2210afc1d33c2e
           Boot ID: 04a0ed0b6e184c708a818938b2d169d1
    Virtualization: vmware
  Operating System: Employee SKU
       CPE OS Name: cpe:/o:redhat:enterprise_linux:7.6:GA:server
            Kernel: Linux 3.10.0-957.el7.x86_64
      Architecture: x86-64
```



### 5. httpd install

5-1) httpd install

```bash
[root@bastion ~]# yum install -y httpd
```

5-2) httpd port 변경

> haproxy 구성 시에 80/443 port가 사용 되므로 겹치치 않도록 httpd port를 8080 (다른 Port)으로 변경

```bash
$ vi /etc/httpd/conf/httpd.conf (설정 파일 수정)
   #Listen 80 
   Listen 8080
--- 생략 ---
```

5-3) Port 방화벽 해제 및 서비스 시작

```bash
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --permanent --add-service=http
firewall-cmd --reload
systemctl enable httpd
systemctl start httpd
systemctl status httpd
```



### 6. DNS 구성

- OpenShift 4.4 환경 구성을 위해서는 DNS 구성이 정방향, 역방향이 다 가능해야 합니다.
- DNS는 name 확인(A records), 인증서 생성(PTR records) 및 서비스 검색(SRV records)에 사용 됩니다.
- OpenShift 4버전은 클러스터 DNS records에 통합 될 clusterid 개념이 있습니다.
  DNS records에는 모두 CLUSTERID.DOMAIN이 포함됩니다.
  즉, clusterid는 FQDN의일부가 되는 것 입니다.



6-1)  정방향 DNS (FORWARD DNS RECORDS)

-  정방향 DNS records는 bootstrap, master, infra, worker node에 대해 생성합니다.

- 또한, api 및 api-int에 대한 항목을 만들어 각각의 load balancer를 가르켜야 합니다.

  (두 항목 모두 동일한 load balancer를 가리킬 수 있음)

6-2)  ETCD DNS RECORDS

- etcd를 생성하기 위해서는 두 개의 record type이 필요합니다.
- 정방향 record는 master의 IP를 가리켜야 합니다.
- 또한, name은 etcd-INDEX여야 하며, 0부터 시작 됩니다.
- 여러 etcd-entries를 가리키는 SRV records도 생성해야 하며, 이 record를 우선 순위 0, 가중치 10 및 포트는 2380으로 설정해야 합니다.

6-3)  역방향 DNS (REVERSE DNS RECORDS)

- 역방향 DNS records는 bootstrap, master, infra, worker node, api 및 api-int에 대해 구성합니다.
- RHEL CoreOS가 모든 node의 호스트 이름을 설정하는 방식이므로 역방향 DNS records가 중요합니다.
- 해당 설정을 하지 않는 경우에는 CoreOS 기동 시에 호스트 이름이 localhost로 설정되어 설치가 됩니다.

6-4) bind, bind-utils install

```bash
$ yum install -y bind bind-utils
```

6-5) DNS Port 방화벽 해제

```bash
firewall-cmd --perm --add-port=53/tcp
firewall-cmd --perm --add-port=53/udp
firewall-cmd --add-service dns --zone=internal --perm 
firewall-cmd --reload
```

6-6) named.conf 수정 

> 파일 위치 :  /etc/named.conf

- 상위 DNS를 외부 네트워크로 나갈 수 있도록 설정하고, 나머지 노드들은 내부 DNS를 바라보게 설정을 하였습니다.

```bash
//
// named.conf
//
// Provided by Red Hat bind package to configure the ISC BIND named(8) DNS
// server as a caching only nameserver (as a localhost DNS resolver only).
//
// See /usr/share/doc/bind*/sample/ for example named configuration files.
//
// See the BIND Administrator's Reference Manual (ARM) for details about the
// configuration located in /usr/share/doc/bind-{version}/Bv9ARM.html

options {
        listen-on port 53 { any; };
        listen-on-v6 port 53 { none; };
        directory       "/var/named";
        dump-file       "/var/named/data/cache_dump.db";
        statistics-file "/var/named/data/named_stats.txt";
        memstatistics-file "/var/named/data/named_mem_stats.txt";
        recursing-file  "/var/named/data/named.recursing";
        secroots-file   "/var/named/data/named.secroots";
        allow-query     { any; };

        /*
         - If you are building an AUTHORITATIVE DNS server, do NOT enable recursion.
         - If you are building a RECURSIVE (caching) DNS server, you need to enable
           recursion.
         - If your recursive DNS server has a public IP address, you MUST enable access
           control to limit queries to your legitimate users. Failing to do so will
           cause your server to become part of large scale DNS amplification
           attacks. Implementing BCP38 within your network would greatly
           reduce such attack surface
        */
        recursion yes;

        forward only;
        forwarders {

        10.64.255.25;   // 상위 DNS 추가 (외부로 나갈 수 있도록)

        };

        dnssec-enable yes;
        dnssec-validation yes;

        /* Path to ISC DLV key */
        bindkeys-file "/etc/named.root.key";

        managed-keys-directory "/var/named/dynamic";

        pid-file "/run/named/named.pid";
        session-keyfile "/run/named/session.key";
};

logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

zone "." IN {
        type hint;
        file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
```

6-7)  named.rfc1912.zones 파일 수정 

> 파일 위치 :  /etc/named.rfc1912.zones

- named.rfc1912.zones의 맨 하단 부분에 추가할 도메인 zone 파일 정보를 입력 합니다.

```bash
// named.rfc1912.zones:
//
// Provided by Red Hat caching-nameserver package
//
// ISC BIND named zone configuration for zones recommended by
// RFC 1912 section 4.1 : localhost TLDs and address zones
// and http://www.ietf.org/internet-drafts/draft-ietf-dnsop-default-local-zones-02.txt
// (c)2007 R W Franks
//
// See /usr/share/doc/bind*/sample/ for example named configuration files.
//

zone "localhost.localdomain" IN {
        type master;
        file "named.localhost";
        allow-update { none; };
};

zone "localhost" IN {
        type master;
        file "named.localhost";
        allow-update { none; };
};

zone "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa" IN {
        type master;
        file "named.loopback";
        allow-update { none; };
};

zone "1.0.0.127.in-addr.arpa" IN {
        type master;
        file "named.loopback";
        allow-update { none; };
};

zone "0.in-addr.arpa" IN {
        type master;
        file "named.empty";
        allow-update { none; };
};

zone "test.com" IN {
        type master;
        file "/var/named/test.com.zone";
        allow-update { none; };
};

zone "168.76.172.in-addr.arpa" IN {
        type master;
        file "/var/named/168.76.172.in-addr.rev";
        allow-update { none; };
};
```

6-8) 정방향 zone 파일 생성

> 파일 위치 : /var/named/test.com.zone

```bash
$TTL 1D
@   IN SOA  @ ns.test.com. (
            1019951001  ; serial
            3H          ; refresh
            1H          ; retry
            1W          ; expiry
            1H )        ; minimum

@           IN NS       ns.test.com.
@           IN A        172.76.168.90

; Ancillary services
lb.ocp          IN A        172.76.168.90

; Bastion or Jumphost
bastion.ocp     IN A        172.76.168.90
ns     IN A       172.76.168.90

; OCP Cluster
bootstrap.ocp   IN A        172.76.168.91

master1.ocp    IN A        172.76.168.101
master2.ocp    IN A        172.76.168.102
master3.ocp    IN A        172.76.168.103

infra1.ocp     IN A        172.76.168.201
infra2.ocp     IN A        172.76.168.202

worker1.ocp    IN A        172.76.168.203
worker2.ocp    IN A        172.76.168.204

etcd-0.ocp      IN A        172.76.168.101
etcd-1.ocp      IN A        172.76.168.102
etcd-2.ocp      IN A        172.76.168.103

_etcd-server-ssl._tcp.ocp.test.com.         IN SRV  0   10  2380         etcd-0.ocp.test.com.
                                            IN SRV  0   10  2380    etcd-1.ocp.test.com.
                                            IN SRV  0   10  2380    etcd-2.ocp.test.com.

api.ocp         IN A    172.76.168.90  ; external LB interface
api-int.ocp     IN A    172.76.168.90  ; internal LB interface
apps.ocp        IN A    172.76.168.90
*.apps.ocp      IN A    172.76.168.90
```

6-9) 역방향 zone 파일 생성

> 파일 위치 : /var/named/168.76.172.in-addr.rev

```bash
@       IN      SOA   test.com. ns.test.com. (
                      179332     ; Serial
                      3H         ; Refresh
                      1H         ; Retry
                      1W         ; Expire
                      1H )       ; Minimum

@      IN NS   ns.
90     IN PTR  ns.
90     IN PTR  bastion.ocp.test.com.
91     IN PTR  bootstrap.ocp.test.com.
101     IN PTR  master1.ocp.test.com.
102     IN PTR  master2.ocp.test.com.
103     IN PTR  master3.ocp.test.com.
201     IN PTR  infra1.ocp.test.com.
202     IN PTR  infra2.ocp.test.com.
203     IN PTR  worker1.ocp.test.com.
204    IN PTR  worker2.ocp.test.com.
90     IN PTR  api.ocp.test.com.
90     IN PTR  api-int.ocp.test.com.
```

> RHCoreOS 호스트 이름 설정 관련하여 역방향 DNS zone 설정이 중요합니다.

6-10) DNS 서비스 등록 및 시작, 상태 확인

```bash
$ systemctl enable named
$ systemctl start named
$ systemctl status named 
```

6-11) 정방향 DNS Resovling 확인

```bash
[root@bastion named]# nslookup bootstrap.ocp.test.com
Server:         172.76.168.90
Address:        172.76.168.90#53

Name:   bootstrap.ocp.test.com
Address: 172.76.168.91

[root@bastion named]# nslookup worker1.ocp.test.com
Server:         172.76.168.90
Address:        172.76.168.90#53

Name:   worker1.ocp.test.com
Address: 172.76.168.203

--- 생략 ---
```

6-12) 역방향 DNS Resolving 확인

```bash
[root@bastion named]# dig -x 172.76.168.91 +short
bootstrap.ocp.test.com.

[root@bastion named]# dig -x 172.76.168.203 +short
worker1.ocp.test.com.

--- 생략 ---
```



### 7. Load Balancer 구성 (Haproxy)

> 내부와 외부 API와 OpenShift 라우터를 forntend하기 위해서는 Load Balnacer가 필요합니다. 

7-1) haproxy install

```bash
$ yum install -y haproxy
```

7-2) haproxy 설정

> 파일 위치 : /etc/haproxy/haproxy.cfg 

```bash
#---------------------------------------------------------------------
# Example configuration for a possible web application.  See the
# full configuration options online.
#
#   http://haproxy.1wt.eu/download/1.4/doc/configuration.txt
#
#---------------------------------------------------------------------

#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # to have these messages end up in /var/log/haproxy.log you will
    # need to:
    #
    # 1) configure syslog to accept network log events.  This is done
    #    by adding the '-r' option to the SYSLOGD_OPTIONS in
    #    /etc/sysconfig/syslog
    #
    # 2) configure local2 events to go to the /var/log/haproxy.log
    #   file. A line like the following can be added to
    #   /etc/sysconfig/syslog
    #
    #    local2.*                       /var/log/haproxy.log
    #
    log         127.0.0.1 local2

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 4000

#---------------------------------------------------------------------
# static backend for serving up images, stylesheets and such
#---------------------------------------------------------------------
backend static
    balance     roundrobin
    server      static 127.0.0.1:4441 check

#---------------------------------------------------------------------
# round robin balancing between the various backends
#---------------------------------------------------------------------
frontend openshift-api-server
    bind *:6443
    default_backend openshift-api-server
    mode tcp
    option tcplog

backend openshift-api-server
    balance source
    mode tcp
    server bootstrap 172.76.168.91:6443 check
    server master1 172.76.168.101:6443 check
    server master2 172.76.168.102:6443 check
    server master3 172.76.168.103:6443 check

frontend machine-config-server
    bind *:22623
    default_backend machine-config-server
    mode tcp
    option tcplog

backend machine-config-server
    balance source
    mode tcp
    server bootstrap 172.76.168.91:22623 check
    server master1 172.76.168.101:22623 check
    server master2 172.76.168.102:22623 check
    server master3 172.76.168.103:22623 check

frontend ingress-http
    bind *:80
    default_backend ingress-http
    mode tcp
    option tcplog

backend ingress-http
    balance source
    mode tcp
    server router1 172.76.168.201:80 check
    server router2 172.76.168.202:80 check

frontend ingress-https
    bind *:443
    default_backend ingress-https
    mode tcp
    option tcplog

backend ingress-https
    balance source
    mode tcp
    server router1 172.76.168.201:443 check
    server router2 172.76.168.202:443 check
```

7-3) 방화벽 해제

```bash
* SELINUX 설정 (HTTP Listener로 정의되지 않은 Port에 대해 SELINUX 권한 허용)
semanage port -a -t http_port_t -p tcp 6443
semanage port -a -t http_port_t -p tcp 22623
```

```bash
firewall-cmd --permanent --add-port=22623/tcp
firewall-cmd --permanent --add-port=6443/tcp
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=http

firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp

firewall-cmd --add-port 22623/tcp --zone=internal --perm
firewall-cmd --add-port 6443/tcp --zone=internal --perm  
firewall-cmd --add-service https --zone=internal --perm  
firewall-cmd --add-service http --zone=internal --perm  
 
firewall-cmd --add-port 6443/tcp --zone=external --perm  
firewall-cmd --add-service https --zone=external --perm  
firewall-cmd --add-service http --zone=external --perm  
firewall-cmd --complete-reload
```

7-4) firewalld port 확인

```bash
[root@bastion ~]# firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: ens192
  sources:
  services: ssh dhcpv6-client http https
  ports: 8080/tcp 53/tcp 53/udp 22623/tcp 6443/tcp 80/tcp 443/tcp
  protocols:
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
```

7-5) haproxy 서비스 등록 및 시작

```bash
systemctl enable haproxy 
systemctl start haproxy
systemctl status haproxy
```



### 8. ssh-key 생성

> 설치 실행 할 cluster install node에서 ssh key 생성과 ssh-agent에 key 등록 합니다.

```bash
[root@bastion ~]#  ssh-keygen -t rsa -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa):
Created directory '/root/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:Y3Hh45+FxM2M5gBkx4138A+zKRYVg5GDtyM1OTRLO8w root@bastion.ocp.skt-poc.com
The key's randomart image is:
+---[RSA 4096]----+
|       .+.o=**+. |
|       . ++*%@.. |
|        . =+E*B  |
|         +.*o+ * |
|        S ..=.+ .|
|       . . o +   |
|            o    |
|                 |
|                 |
+----[SHA256]-----+

[root@bastion ~]# eval "$(ssh-agent -s)"
Agent pid 21360
[root@bastion ~]# ssh-add ~/.ssh/id_rsa
Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)
```



### 9. install 사전 확인

9-1) ip 확인

```bash
[root@bastion ~]# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:9a:3d:4f brd ff:ff:ff:ff:ff:ff
    inet 10.76.168.90/23 brd 10.76.169.255 scope global noprefixroute ens192
       valid_lft forever preferred_lft forever
    inet6 2620:52:0:4ca8:250:56ff:fe9a:3d4f/64 scope global mngtmpaddr dynamic
       valid_lft 2591962sec preferred_lft 604762sec
    inet6 fe80::250:56ff:fe9a:3d4f/64 scope link
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:9a:c4:5b brd ff:ff:ff:ff:ff:ff
    inet 172.76.168.90/23 brd 172.76.169.255 scope global noprefixroute ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe9a:c45b/64 scope link
       valid_lft forever preferred_lft forever
```

9-2)  DNS 서비스 확인

```bash
$ systemctl status named
```

9-3) haproxy 서비스 확인

```bash
$ systemctl status haproxy
```



### 10. install-config.yaml 생성

10-1) install에 필요한 파일 다운 로드

- wget이 없는 경우 설치 후 진행 

  - /var/www/html/ocp 디렉토리에서 명령어 실행
  
  ```bash
  wget https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/4.4/4.4.3/rhcos-4.4.3-x86_64-installer.x86_64.iso
  wget https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/4.4/4.4.3/rhcos-4.4.3-x86_64-metal.x86_64.raw.gz
  wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.3.10/openshift-install-linux-4.4.3.tar.gz
wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.3.10/openshift-client-linux-4.4.3.tar.gz
  ```

10-2) openshift-install, openshift-client install 파일을 압축 해제 (OpenShift CLI Install)

```bash
tar -xzf /var/www/html/openshift-client-linux-4.4.3.tar.gz -C /usr/local/bin/
tar -xzf /var/www/html/openshift-install-linux-4.4.3.tar.gz -C /usr/local/bin/
```

10-3) install-config.yaml 생성

> OpenShift를 설치할 디렉토리를 생성한 후 install-config.yaml을 작성합니다.
>
> 본 가이드의 설치 디렉토리는 /var/www/html/ocp 입니다.
>
> install-config.yaml은 OpenShift 4.3 Cluster 구성을 위한 ignition 파일을 생성하는데 필요하며, 해당 파일은 ignition 파일을 생성하고 삭제되므로 반드시 백업을 한 후 작업을 하는 것이 좋습니다.

- [x] 생성된 ignition config 파일은 24시간 동안 유효한 인증서를 포함하고 있어서 반드시 24시간 내에 OpenShift Cluster 구성을 완료해야 합니다.

- [x] 또한, 설치가 완료된 이후에도 24시간 내에 master node는 종료하면 안됩니다.

- [x] 24시간 이후에 master node의 인증서가 갱신 되기 때문입니다. 

  - vSphere install-config.yaml Sample 

    ```yaml
    apiVersion: v1
    baseDomain: example.com 
    compute:
    - hyperthreading: Enabled   
      name: worker
      replicas: 0 
    controlPlane:
      hyperthreading: Enabled   
      name: master
      replicas: 3 
    metadata:
      name: test 
    platform:
      vsphere:
        vcenter: your.vcenter.server 
        username: username 
        password: password 
        datacenter: datacenter 
        defaultDatastore: datastore 
    fips: false 
    pullSecret: '{"auths": ...}' 
    sshKey: 'ssh-ed25519 AAAA...' 
    ```

  - install-config.yaml

    ```bash
    apiVersion: v1
    baseDomain: ocp
    compute:
    - hyperthreading: Enabled
      name: worker
      replicas: 0
    controlPlane:
      hyperthreading: Enabled
      name: master
      replicas: 3
    metadata:
      name: ocp
    platform:
      vsphere:
        vcenter: 10.76.168.10
        username: administrator@vsphere.local
        password: Redhat1!
        datacenter: Datacenter
        defaultDatastore: glusternfs
    pullSecret: ''
    sshKey: ''
    ```

    - baseDomain : skt-poc.com (도메인 이름)
    - name : ocp (Cluster 이름)
    - pullSecret: cloud.openshift.com에서 다운 받은 pull-secret 파일 입력
    - sshKey: 위에서 생성한 ssh-key의 /root/.ssh/id_rsa.pub 내용 추가



### 11. ignition 파일 생성

11-1) install-config.yaml 생성

- [x] 생성된 ignition config 파일은 24시간 동안 유효한 인증서를 포함하고 있어서 반드시 24시간 내에 OpenShift Cluster 구성을 완료해야 합니다.
- [x] ingnition 파일을 생성하면 install-config.yaml 파일은 삭제되므로 작업 전에 백업을 합니다

```bash
[root@bastion ocp]# cp install-config.yaml install-config.yaml_bak
```

11-2)  Kubernetest manifests file 생성

```bash
[root@bastion ~]# openshift-install create manifests --dir=/var/www/html/ocp
INFO Consuming "Install Config" from target directory
WARNING Making control-plane schedulable by setting MastersSchedulable to true for Scheduler cluster settings
```

- /var/www/html/ocp/manifests/cluster-scheduler-02-config.yml 에서  mastersSchedulable  값을 =='true->false'==로 변경 후 저장

  ```bash
  [root@bastion ocp]# cd manifests/
  [root@bastion manifests]# sed -i 's/mastersSchedulable: true/mastersSchedulable: false/g' cluster-scheduler-02-config.yml
  [root@bastion manifests]# cat cluster-scheduler-02-config.yml
  apiVersion: config.openshift.io/v1
  kind: Scheduler
  metadata:
    creationTimestamp: null
    name: cluster
  spec:
    mastersSchedulable: false
    policy:
      name: ""
status: {}
  ```
  
  > 현재 Kubernetes 제한으로 인해 control-plane 머신에서 실행되는 router pod에 수신 로드 밸런서가 도달 할 수 없습니다. 향후 minor 버전의 OpenShift Container Platform에서는이 단계가 필요하지 않을 수 있습니다.
  
  > 설치 관리자가 master를 예약 할 수 있음을 알려줍니다. 이 설치를 위해 master를 예약 할 수 없도록 설정해야합니다.

11-3) Modifying advanced network configuration parameters 

> <installation_directory>/manifests/ directory 에 cluster-network-03-config.yml 파일 생성

```yaml
apiVersion: operator.openshift.io/v1
kind: Network
metadata:
  name: cluster
spec: 
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  serviceNetwork:
  - 172.30.0.0/16
  defaultNetwork:
    type: OpenShiftSDN
    openshiftSDNConfig:
      mode: NetworkPolicy
      mtu: 1450
      vxlanPort: 4789
```

> 디렉토리 내에 파일 확인 

```bash
ls <installation_directory>/manifests/cluster-network-*
```

> manifests 디렉토리 및 해당 파일은 ignition 생성 명령어를 실행할 경우 디렉토리 내에서 사라집니다. 

11-4)  ignition config 파일 생성

- ignition config 파일 생성

```bash
[root@bastion ocp]# openshift-install create ignition-configs --dir=/var/www/html/ocp
INFO Consuming "Install Config" from target directory
INFO Consuming "Master Machines" from target directory
INFO Consuming "Common Manifests" from target directory
INFO Consuming "Worker Machines" from target directory
INFO Consuming "Openshift Manifests" from target directory
```

> 아래와 같이 디렉토리 및 파일이 생성됩니다.

```bash
├── auth
│   ├── kubeadmin-password
│   └── kubeconfig
├── bootstrap.ign
├── master.ign
├── metadata.json
└── worker.ign
```

11-5) static ip를 위한 ignition 파일 생성

- 원활한 작업을 위해 ignition 디렉토리를 생성하여 해당 디렉토리안에 각 node의 별도 ignition 파일을 생성합니다.

  ```bash
  [root@bastion ocp]# mkdir ign
  [root@bastion ocp]# ls -rlt
  total 308
  -rw-r--r--. 1 root root   3875 Feb 11 08:18 install-config.yaml_bak
  drwxr-x---. 2 root root     50 Feb 11 08:19 auth
  -rw-r-----. 1 root root   1821 Feb 11 08:19 master.ign
  -rw-r-----. 1 root root   1821 Feb 11 08:19 worker.ign
  -rw-r-----. 1 root root 297360 Feb 11 08:19 bootstrap.ign
  -rw-r-----. 1 root root     94 Feb 11 08:19 metadata.json
  drwxr-xr-x. 2 root root      6 Feb 11 08:21 ign  // 디렉토리 생성 확인
  ```

- 기본 ignition 파일로 각 node의 별도 ignition 파일 복사 및 이동

  - 파일 복사
  
  ```bash
  cp bootstrap.ign poc_bootstrap.ign
  cp master.ign poc_master1.ign
  cp master.ign poc_master2.ign
  cp master.ign poc_master3.ign
  cp worker.ign poc_infra1.ign
  cp worker.ign poc_infra2.ign
  cp worker.ign poc_worker1.ign
  cp worker.ign poc_worker2.ign
  ```
  
  - 파일 이동
  
  ```bash
  mv poc_bootstrap.ign /var/www/html/ign
  mv poc_master1.ign /var/www/html/ign
  mv poc_master2.ign /var/www/html/ign
  mv poc_master3.ign /var/www/html/ign
  mv poc_infra1.ign /var/www/html/ign
  mv poc_infra2.ign /var/www/html/ign
  mv poc_worker1.ign /var/www/html/ign
  mv poc_worker2.ign /var/www/html/ign
  ```

11-4) 개별 node ignition 구성을 위한 network script 생성

- bootstrap (ex. boot-net.txt)

  > bootstrap network-script 내용 작성
  
  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.91
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- master1 (ex. master1-net.txt)

  > master1 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.101
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- master2 (ex. master2-net.txt)

  > master2 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.102
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- master3 (ex. master3-net.txt)

  > master3 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.103
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- infra1 (ex. infra1-net.txt)

  > infra1 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.201
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- infra2 (ex. infra2-net.txt)

  > infra2 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.202
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- worker1 (ex. worker1-net.txt)

  > worker1 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.203
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```

- worker2 (ex. worker2-net.txt)

  > worker2 network-script 내용 작성

  ```bash
  TYPE=Ethernet
  PROXY_METHOD=none
  BROWSER_ONLY=no
  BOOTPROTO=static
  IPADDR=172.76.168.204
  NETMASK=255.255.254.0
  GATEWAY=172.76.168.90
  DEFROUTE=yes
  IPV4_FAILURE_FATAL=no
  NAME=ens192
  DEVICE=ens192
  ONBOOT=yes
  DOMAIN=ocp.test.com
  DNS1=172.76.168.90
  ```


11-5) network-script를 base64 인코딩

- script로 실행

  ```bash
  [root@bastion ~]# for list in `ls -1 *.txt`; do echo $list ; cat $list | base64 -w0 ; echo \ ; done
  ```

- 결과값

  ```bash
  boot-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjA3Ck5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  infra1-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjA5Ck5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  infra2-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjEwCk5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  master1-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMTk5Ck5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  master2-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjAwCk5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  master3-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjAxCk5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  worker1-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjAyCk5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  worker2-net.txt
  VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNDAuODkuMjAzCk5FVE1BU0s9MjU1LjI1NS4yNTUuMApHQVRFV0FZPTEwLjQwLjg5LjEKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcC5za3QtcG9jLmNvbQpETlMxPTEwLjQwLjg5LjIwOAo=
  ```

11-6) ignition 파일 수정

> ignition 파일 수정 전에 jq를 이용하여 yaml 형태로 파일 변환

```bash
for list in `ls -1 *.ign`; do echo $list ; cat $list | jq > jq-$list; done
```

- 변환한 파일에 아래 예시 내용 추가 

- bootstrap

  ```yaml
  "storage": {
  "files": [
  // 해당 부분 아래 부터 추가
  {
  "contents": {
    "source": "data:text/plain;charset=utf-8,bootstrap.ocp.test.com",
    "verification": {}
  },
  "filesystem": "root",
  "group": {},
  "mode": 420,
  "path": "/etc/hostname",
  "user": {}
  },
  {
  "contents": {
    "source": "data:text/plain;charset=utf-8;base64,VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNzYuMTY4LjQyCk5FVE1BU0s9MjU1LjI1NS4yNTQuMApHQVRFV0FZPTEwLjc2LjE2OS4yNTQKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcDQuc2tiYi1wb2MuY29tCkROUzE9MTAuNzYuMTY4LjQwCg==",
    "verification": {}
  },
  "filesystem": "root",
  "path": "/etc/sysconfig/network-scripts/ifcfg-ens192",
  "mode": 420,
  "user": {}
  }, // 여기까지 추가
  ]
  },
  ```
> boot.ign 파일에 storage 섹션 아래에 위의 내용을 추가합니다.

- master, infra, worker의 경우 형식이 비슷하므로 한 가지 예시만 작성합니다.

    - master

      > master의 경우에도 기존 파일 제일 하단의 `storage {}` 섹션 사이에 해당 내용 전체를 추가합니다.
      >
      > 해당 내용은 예시 이므로, 환경에 맞게 설정 후 반영을 해주셔야 합니다.
      
      ```bash
       "files": [
          {
          "contents": {
            "source": "data:text/plain;charset=utf-8,master1.ocp.gpu-poc.com",
            "verification": {}
          },
          "filesystem": "root",
          "group": {},
          "mode": 420,
          "path": "/etc/hostname",
          "user": {}
          },
          {
          "contents": {
            "source": "data:text/plain;charset=utf-8;base64,VFlQRT1FdGhlcm5ldApQUk9YWV9NRVRIT0Q9bm9uZQpCUk9XU0VSX09OTFk9bm8KQk9PVFBST1RPPXN0YXRpYwpJUEFERFI9MTAuNzYuMTY4LjQxCk5FVE1BU0s9MjU1LjI1NS4yNTQuMApHQVRFV0FZPTEwLjc2LjE2OS4yNTQKREVGUk9VVEU9eWVzCklQVjRfRkFJTFVSRV9GQVRBTD1ubwpOQU1FPWVuczE5MgpERVZJQ0U9ZW5zMTkyCk9OQk9PVD15ZXMKRE9NQUlOPW9jcDQuc2tiYi1wb2MuY29tCkROUzE9MTAuNzYuMTY4LjQwCg==",
            "verification": {}
          },
          "filesystem": "root",
          "path": "/etc/sysconfig/network-scripts/ifcfg-ens192",
          "mode": 420,
          "user": {}
          }
          ]
      ```
      
    
- 수정한 ignition파일이 yaml 형식이면 그대로 사용해도 되고, 한줄로 변경해서 사용해도 됩니다.

  - 한줄로 변환 할 경우

    ```bash
    [root@bastion ign]# cat jq_after.sh
    cat jq-poc_bootstrap.ign | jq -c > boot1.ign
    cat jq-poc_master1.ign | jq -c > master1.ign
    cat jq-poc_master2.ign | jq -c > master2.ign
    cat jq-poc_master3.ign | jq -c > master3.ign
    cat jq-poc_infra1.ign | jq -c > infra1.ign
    cat jq-poc_infra2.ign | jq -c > infra2.ign
    cat jq-poc_worker1.ign | jq -c > worker1.ign
    cat jq-poc_worker2.ign | jq -c > worker2.ign
    ```

  > 위와 같이 작업을 한 경우에 설치를 위한 사전 작업이 거의 된 것 입니다.




### 12. 설치 사전 확인

> 설치 전에 사전에 확인해야 할 부분을 확인 합니다.

12-1) ip 확인 

```bash
[root@bastion ign]# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:9a:3d:4f brd ff:ff:ff:ff:ff:ff
    inet 10.76.168.90/23 brd 10.76.169.255 scope global noprefixroute ens192
       valid_lft forever preferred_lft forever
    inet6 2620:52:0:4ca8:250:56ff:fe9a:3d4f/64 scope global mngtmpaddr dynamic
       valid_lft 2591600sec preferred_lft 604400sec
    inet6 fe80::250:56ff:fe9a:3d4f/64 scope link
       valid_lft forever preferred_lft forever
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:9a:c4:5b brd ff:ff:ff:ff:ff:ff
    inet 172.76.168.90/23 brd 172.76.169.255 scope global noprefixroute ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe9a:c45b/64 scope link
       valid_lft forever preferred_lft forever
```

12-2) httpd 상태 확인

```bash
[root@bastion ign]# systemctl status httpd | grep Active
   Active: active (running) since Tue 2020-05-12 04:13:21 EDT; 23min ago
```

12-3) dns 확인

```bash
[root@bastion ign]# systemctl status named | grep Active
   Active: active (running) since Tue 2020-05-12 04:15:25 EDT; 21min ago
```

- resolving 확인

  ```bash
  [root@bastion ign]# nslookup bootstrap.ocp.gpu-poc.com
  Server:         100.100.0.170
  Address:        100.100.0.170#53
  
  Name:   bootstrap.ocp.gpu-poc.com
  Address: 100.100.0.171
  
  [root@bastion ign]# dig -x 100.100.0.171 +short
  bootstrap.ocp.gpu-poc.com.
  
  --- 생략 ---
  ```

12-4) haporxy 확인

```bash
[root@bastion ign]#  systemctl status haproxy | grep Active
   Active: active (running) since Tue 2020-05-12 04:17:24 EDT; 20min ago
```



### 13. 노드 구성

* bootstrap node를 시작으로 OCP Cluster를 구성합니다.

* 각 서버를 설치 할 때, TAB Key를 눌러서 아래 명령어를 입력하고 설치를 시작합니다.

* 한줄로 입력 되어야 합니다.

  ```bash
  coreos.inst.install_dev=sda coreos.inst.image_url=http://172.76.168.90:8080/bios.raw.gz
  coreos.inst.ignition_url=http://172.76.168.90:8080/ocp/ign/boot1.ign
  ip=172.76.168.91::172.76.168.90:255.255.254.0:bootstrap.ocp.test.com:ens192:none nameserver=172.76.168.90
  ```

- bootstrap node가 정상적으로 올라오면, master node 3대를 순차적으로 설치를 시작합니다.

- master node (control-plane) 3대가 정상적으로 올라와야 cluster에 대한 healthy check가 commit 되고, bootstrap을 이용한 cluster 구성이 진행됩니다.

  - bootstrap monitoring log message

  ```bash
  Apr 08 02:59:47 bootstrap.ocp.skt-poc.com podman[11930]: 2020-04-08 02:59:47.560625839 +0000 UTC m=+405.456802793 container died deec6b62dcd123e80bb692e667c01067b0355590c439838bb188ec627f4acbed (image=quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:222fbfd3323ec347babbda1a66929019221fcee82cfc324a173b39b218cf6c4b, name=eloquent_kepler)
  Apr 08 02:59:47 bootstrap.ocp.skt-poc.com podman[11930]: 2020-04-08 02:59:47.632703431 +0000 UTC m=+405.528880379 container remove deec6b62dcd123e80bb692e667c01067b0355590c439838bb188ec627f4acbed (image=quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:222fbfd3323ec347babbda1a66929019221fcee82cfc324a173b39b218cf6c4b, name=eloquent_kepler)
  Apr 08 02:59:47 bootstrap.ocp.skt-poc.com bootkube.sh[3012]: bootkube.service complete
  ```

- bootstrap complete install status monitoring command

  ```bash
  # openshift-install wait-for bootstrap-complete --dir=/root/ocp --log-level debug
  ```

### 14. Logging in to the Cluster

cluster kubeconfig 파일을 export해서 기본 시스템 사용자로 cluster에 로그인 할 수 있습니다. kubeconfig 파일에는 CLI가 클라이언트를 올바른 cluster 및 API 서버에 연결하는데 사용하는 cluster에 대한 정보가 포함되어 있습니다. 이 파일은 cluster에 따라 다르며 Openshift Container Platform 설치 중에 생성 됩니다.

-  Export the `kubeadmin` credentials:

  ```bash
  export KUBECONFIG=/root/ocp/auth/kubeconfig
  ```

-  Verify you can run `oc` commands successfully using the exported configuration: 

  ```bash
  $ oc whoami
  system:admin
  ```



### 15. Approving the CSRs for your machines

Machine을 cluster에 추가하면 추가 한 각 Machine에 대해 두 개의 보류중인 인증서 서명 요청 (CSR)이 생성됩니다. 이러한 CSR이 승인되었는지 확인하거나 필요한 경우 직접 승인하십시오. 

-  Confirm that the cluster recognizes the machines: 

  ```bash
  $ oc get nodes
  
  NAME      STATUS    ROLES   AGE  VERSION
  master1  Ready     master  63m  v1.16.2
  master2  Ready     master  63m  v1.16.2
  master3  Ready     master  64m  v1.16.2
  router1  NotReady  worker  76s  v1.16.2
  router2  NotReady  worker  70s  v1.16.2
  router3  NotReady  worker  70s  v1.16.2
  ```

- 보류중인 인증서 서명 요청 (CSR)을 검토하고 클러스터에 추가 한 각 시스템에 대해 보류 중 또는 승인 됨 상태의 클라이언트 및 서버 요청이 표시되는지 확인

  ```bash
  [root@bastion ocp]# oc get csr
  NAME        AGE    REQUESTOR                                                                   CONDITION
  csr-2765q   90m    system:serviceaccount:openshift-machine-config-operator:node-bootstrapper   Approved,Issued
  csr-4h2bp   143m   system:serviceaccount:openshift-machine-config-operator:node-bootstrapper   Approved,Issued
  csr-4w9cq   74m    system:node:router3.ocp.skt-poc.com                                         Pending
  csr-58d4c   136m   system:serviceaccount:openshift-machine-config-operator:node-bootstrapper   Approved,Issued
  --- 생략 ---
  ```

  -  To approve them individually, run the following command for each valid CSR 

    ```bash
    $ oc adm certificate approve csr-4w9cq
    ```

  -  If all the CSRs are valid, approve them all by running the following command :

    ```bash
    $ oc get csr -ojson | jq -r '.items[] | select(.status == {} ) | .metadata.name' | xargs oc adm certificate approve
    ```



### 16. Initial Operator configuration

Control-Plane이 초기화 된 후에는 일부 Operator가 즉시 사용할 수 있도록 일부 Operator를 즉시 구성해야합니다.

-  Watch the cluster components come online:

  ```bash
  [root@bastion ign]# oc get co
  NAME                                       VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE
  authentication                             4.3.10    True        False         False      28s
  cloud-credential                           4.3.10    True        False         False      34m
  cluster-autoscaler                         4.3.10    True        False         False      19m
  console                                    4.3.10    True        False         False      118s
  dns                                        4.3.10    True        False         False      29m
  image-registry                             4.3.10    True        False         False      24m
  ingress                                    4.3.10    True        False         False      6m18s
  insights                                   4.3.10    True        False         False      24m
  kube-apiserver                             4.3.10    True        False          False      28m
  kube-controller-manager                    4.3.10    True        False         False      27m
  kube-scheduler                             4.3.10    True        False         False      27m
  machine-api                                4.3.10    True        False         False      29m
  machine-config                             4.3.10    True        False         False      5m21s
  marketplace                                4.3.10    True        False         False      21m
  monitoring                                 4.3.10    True        False         False      3m26s
  network                                    4.3.10    True        False         False      29m
  node-tuning                                4.3.10    True        False         False      16m
  openshift-apiserver                        4.3.10    True        False         False      10m
  openshift-controller-manager               4.3.10    True        False         False      28m
  openshift-samples                          4.3.10    True        False         False      10m
  operator-lifecycle-manager                 4.3.10    True        False         False      26m
  operator-lifecycle-manager-catalog         4.3.10    True        False         False      26m
  operator-lifecycle-manager-packageserver   4.3.10    True        False         False      22m
  service-ca                                 4.3.10    True        False         False      31m
  service-catalog-apiserver                  4.3.10    True        False         False      26m
  service-catalog-controller-manager         4.3.10    True        False         False      26m
  storage  
  ```
  
- openshift complete install status monitoring command

  ```bash
  [root@bastion ign]# openshift-install wait-for install-complete --dir=/var/www/html/ocp --log-level debug
  DEBUG OpenShift Installer 4.3.10
  DEBUG Built from commit 0a7f198c1d5667152ef5982fd2fc0c22abc4336f
  DEBUG Fetching Install Config...
  DEBUG Loading Install Config...
  DEBUG   Loading SSH Key...
  DEBUG   Loading Base Domain...
  DEBUG     Loading Platform...
  DEBUG   Loading Cluster Name...
  DEBUG     Loading Base Domain...
  DEBUG     Loading Platform...
  DEBUG   Loading Pull Secret...
  DEBUG   Loading Platform...
  DEBUG Using Install Config loaded from state file
  DEBUG Reusing previously-fetched Install Config
  INFO Waiting up to 30m0s for the cluster at https://api.ocp.skt-poc.com:6443 to initialize...
  DEBUG Still waiting for the cluster to initialize: Working towards 4.3.10: 96% complete
  DEBUG Still waiting for the cluster to initialize: Some cluster operators are still updating: authentication, cluster-autoscaler, console, ingress, marketplace, monitoring, openshift-apiserver, openshift-samples
  DEBUG Still waiting for the cluster to initialize: Some cluster operators are still updating: authentication, cluster-autoscaler, console, ingress, marketplace, monitoring, openshift-apiserver, openshift-samples
  DEBUG Still waiting for the cluster to initialize: Some cluster operators are still updating: authentication, cluster-autoscaler, console, ingress, marketplace, monitoring, openshift-apiserver, openshift-samples
  DEBUG Still waiting for the cluster to initialize: Working towards 4.3.10: 100% complete
  DEBUG Cluster is initialized
  INFO Waiting up to 10m0s for the openshift-console route to be created...
  DEBUG Route found in openshift-console namespace: console
  DEBUG Route found in openshift-console namespace: downloads
  DEBUG OpenShift console route is created
  INFO Install complete!
  INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/var/www/html/ocp/auth/kubeconfig'
  INFO Access the OpenShift web-console here: https://console-openshift-console.apps.ocp.skt-poc.com
  INFO Login to the console with user: kubeadmin, password: Bo7IA-LLIjn-HoYjS-zUCPA
  ```



### 17.  Image registry removed during installation

공유 가능한 객체 스토리지를 제공하지 않는 플랫폼에서 OpenShift Image Registry Operator는 자체를 제거됨으로 부트 스트랩합니다. 이를 통해 openshift-installer는 이러한 플랫폼 유형에서 설치를 완료 할 수 있습니다. 

==설치 후 ManagementState를 Removed에서 Managed로 전환하도록 Image Registry Operator 구성을 편집해야합니다.==

- empty Directory에 image registry storage 설정

  ```bash
  oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"storage":{"emptyDir":{}}}}'
  ```

-  ManagementState를 Removed에서 Managed로 전환하도록 Image Registry Operator 구성을 편집

  ```bash
  oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"managementState": "Managed"}}'
  ```

- 위의 설정과 관련하여 Image Registry가 설치 동안 제거 된 경우에는 콘솔에서 다음과 경고 메시지를 볼 수 있습니다.

  ```bash
  "Image Registry has been removed. ImageStreamTags, BuildConfigs and DeploymentConfigs which reference ImageStreamTags may not work as expected. Please configure storage and update the config to Managed state by editing configs.imageregistry.operator.openshift.io."
  ```

  

### 18. Console 접속

> Console 접속을 위한 hosts 파일 수정

```bash
10.40.89.208          console-openshift-console.apps.ocp.skt-poc.com
10.40.89.208          oauth-openshift.apps.ocp.skt-poc.com
```



### 19. 계정 생성 (Configuring an HTPasswd identity provider)

19-1) 계정 생성

- OCP 설치 디렉토리에서 계정 생성 명령어 실행

```bash
# htpasswd -c -B -b ./htpasswd admin redhat
```

19-2) HTPasswd Secret 생성

```bash
[root@bastion ocp]# oc create secret generic htpass-secret --from-file=htpasswd=./htpasswd -n openshift-config
secret/opentlc-ldap-secret created
```

- Sample HTPasswd CR 

  > 다음 Custom Resource (CR)은 HTPasswd identity provider의 매개 변수 및 허용 가능한 값을 보여준다.

  - sample yaml

  ```yaml
  apiVersion: config.openshift.io/v1
  kind: OAuth
  metadata:
    name: cluster
  spec:
    identityProviders:
    - name: my_htpasswd_provider 1)
      mappingMethod: claim 2)
      type: HTPasswd
      htpasswd:
        fileData:
          name: htpass-secret 3)
  ```

  - 1) 이 제공자 이름은 제공자 이름에 접두어로 ID 이름을 형성합니다.
  - 2) 이 공급자의 ID와 사용자 개체간에 매핑을 설정하는 방법을 제어합니다.
  - 3) htpasswd를 사용하여 생성 된 파일을 포함하는 기존 secret

- yaml

  ```yaml
  vi passwd.yaml
  apiVersion: config.openshift.io/v1
  kind: OAuth
  metadata:
    name: cluster
  spec:
    identityProviders:
    - name: skt-poc
      mappingMethod: claim 
      type: HTPasswd
      htpasswd:
        fileData:
          name: htpass-secret 
  ```

- Cluster에 identity provider 추가

  > 위에서 생성한 passwd.yaml을 적용한다.

  ```bash
  [root@registry ocp]# oc apply -f passwd.yaml
  Warning: oc apply should be used on resource created by either oc create --save-config or oc apply
  ```

19-3) Grant to cluster-admin

```bash
$ oc adm policy add-cluster-role-to-user cluster-admin admin
clusterrole.rbac.authorization.k8s.io/cluster-admin added: "admin"
```

- oc login 확인

  - 새로 생성한 계정으로 바로 로그인이 되지 않을 경우 조금 기다렸다가 하면 됩니다.
  - 변경 사항이 적용 되는데 시간이 조금 걸릴 수 있습니다.
  
  ```bash
  # oc login -u <username>
  
  [root@bastion ocp]# oc login -u admin
  Authentication required for https://api.ocp.skbb-poc.com:6443 (openshift)
  Username: admin
  Password:
  Login successful.
  
  You have access to 53 projects, the list has been suppressed. You can list all projects with 'oc projects'
  
  Using project "default".
  [root@bastion ocp]# oc projects
  You have access to the following projects and can switch between them with 'oc project <projectname>':
  
    * default
      kube-node-lease
      kube-public
      kube-system
      openshift
      openshift-apiserver
      openshift-apiserver-operator
      openshift-authentication
      openshift-authentication-operator
      openshift-cloud-credential-operator
      openshift-cluster-machine-approver
      openshift-cluster-node-tuning-operator
      openshift-cluster-samples-operator
      
  ---- 생략 ----
  
  Using project "default" on server "https://api.ocp.skbb-poc.com:6443".
  ```
  
- login이 성공하면 id 확인 

  ```bash
  [root@bastion ocp]# oc whoami
  admin
  ```

  - admin 계정으로도 Console  접속이 가능하다.

- cluster-admin 권한 부여

  ```bash
  # oc adm policy add-cluster-role-to-user cluster-admin admin
  ```

19-4) kubeadmin 계정 삭제

```bash
oc delete secrets kubeadmin -n kube-system
```



### 20. RHCOS TimeZone Change & chrony Settings

- CoreOS 접속

- `sudo -i`접속 후 다음 명령어 실행

  ```bash
  timedatectl set-timezone Asia/Seoul
  ```

  - 재기동을 해도 이전 시간대로 돌아가지 않음

20-1) Chrony Install (bastion)

- chrony install

  ```bash 
  $ yum install -y chrony
  ```

- chrony configuration (/etc/chrony.conf)

  ```bash
  # Use public servers from the pool.ntp.org project.
  # Please consider joining the pool (http://www.pool.ntp.org/join.html).
  server bastion.ocp.skt-poc.com iburst // chrony server settings
  #server 0.rhel.pool.ntp.org iburst
  #server 1.rhel.pool.ntp.org iburst
  #server 2.rhel.pool.ntp.org iburst
  #server 3.rhel.pool.ntp.org iburst
  
  # Record the rate at which the system clock gains/losses time.
  driftfile /var/lib/chrony/drift
  
  # Allow the system clock to be stepped in the first three updates
  # if its offset is larger than 1 second.
  makestep 1.0 3
  
  # Enable kernel synchronization of the real-time clock (RTC).
  rtcsync
  
  # Enable hardware timestamping on all interfaces that support it.
  #hwtimestamp *
  
  # Increase the minimum number of selectable sources required to adjust
  # the system clock.
  #minsources 2
  
  # Allow NTP client access from local network.
  allow 10.40.89.0/24  // local network settings
  #allow 192.168.0.0/16
  
  # Serve time even if not synchronized to a time source.
  local stratum 3  // local stratum settings
  #local stratum 10
  
  # Specify file containing keys for NTP authentication.
  #keyfile /etc/chrony.keys
  
  # Specify directory for log files.
  logdir /var/log/chrony
  
  # Select which information is logged.
  #log measurements statistics tracking
  ```

- chrony restart

  ```bash
  $ systemctl restart chronyd
  ```

- chrony settings 확인

  ```bash
  [root@bastion ~]# chronyc sources -v
  210 Number of sources = 1
  
    .-- Source mode  '^' = server, '=' = peer, '#' = local clock.
   / .- Source state '*' = current synced, '+' = combined , '-' = not combined,
  | /   '?' = unreachable, 'x' = time may be in error, '~' = time too variable.
  ||                                                 .- xxxx [ yyyy ] +/- zzzz
  ||      Reachability register (octal) -.           |  xxxx = adjusted offset,
  ||      Log2(Polling interval) --.      |          |  yyyy = measured offset,
  ||                                \     |          |  zzzz = estimated error.
  ||                                 |    |           \
  MS Name/IP address         Stratum Poll Reach LastRx Last sample
  ===============================================================================
  ^* bastion.ocp.skt-poc.com       3   6   377   618   +271ns[-5660ns] +/-   14us
  ```

- port 방화벽 해제 (bastion 서버만)

  ```bash
  firewall-cmd --perm --add-service=ntp
  firewall-cmd --reload
  firewall-cmd --perm --add-port=123/tcp
  firewall-cmd --perm --add-port=123/udp
  firewall-cmd --reload
  ```

20-2) Configuring chrony time service

chrony.conf 파일의 내용을 수정하고 해당 내용을 MachineConfig로 노드에 전달하여 chrony time service (chronyd)에서 사용하는 시간 서버 및 관련 설정을 설정할 수 있습니다.

- Create the contents of the chrony.conf file and encode it as base64. For example

  ```bash
  [root@bastion ~]# cat chrony.conf
  server bastion.ocp.skt-poc.com iburst
  driftfile /var/lib/chrony/drift
  makestep 1.0 3
  rtcsync
  logdir /var/log/chrony
  ```

- base64 인코딩

  ```bash
  [root@bastion ~]# cat chrony.conf | base64 -w0;
  c2VydmVyIGNsb2NrLnJlZGhhdC5jb20gaWJ1cnN0CmRyaWZ0ZmlsZSAvdmFyL2xpYi9jaHJvbnkvZHJpZnQKbWFrZXN0ZXAgMS4wIDMKcnRjc3luYwpsb2dkaXIgL3Zhci9sb2cvY2hyb255Cg==
  ```

-  MachineConfig 파일을 만들어서 base64 부분을 대체합니다.
  해당 예저는 `master node`에 추가하는 예제이고, worker로 변경해서 `worker role`에도 추가 할 수 있음

  ```bash
  cat << EOF > ./masters-chrony-configuration.yaml
  apiVersion: machineconfiguration.openshift.io/v1
  kind: MachineConfig
  metadata:
    labels:
      machineconfiguration.openshift.io/role: master
    name: masters-chrony-configuration
  spec:
    config:
      ignition:
        config: {}
        security:
          tls: {}
        timeouts: {}
        version: 2.2.0
      networkd: {}
      passwd: {}
      storage:
        files:
        - contents:
            source: data:text/plain;charset=utf-8;base64,c2VydmVyIGJhc3Rpb24ub2NwLnNrdC1wb2MuY29tIGlidXJzdApkcmlmdGZpbGUgL3Zhci9saWIvY2hyb255L2RyaWZ0Cm1ha2VzdGVwIDEuMCAzCnJ0Y3N5bmMKbG9nZGlyIC92YXIvbG9nL2Nocm9ueQo=
            verification: {}
          filesystem: root
          mode: 420
          path: /etc/chrony.conf
    osImageURL: ""
  EOF
  ```

- `worker role`예시 

  ```bash
  cat << EOF > ./workers-chrony-configuration.yaml
  apiVersion: machineconfiguration.openshift.io/v1
  kind: MachineConfig
  metadata:
    labels:
      machineconfiguration.openshift.io/role: worker
    name: workers-chrony-configuration
  spec:
    config:
      ignition:
        config: {}
        security:
          tls: {}
        timeouts: {}
        version: 2.2.0
      networkd: {}
      passwd: {}
      storage:
        files:
        - contents:
            source: data:text/plain;charset=utf-8;base64,c2VydmVyIGJhc3Rpb24ub2NwLnNrdC1wb2MuY29tIGlidXJzdApkcmlmdGZpbGUgL3Zhci9saWIvY2hyb255L2RyaWZ0Cm1ha2VzdGVwIDEuMCAzCnJ0Y3N5bmMKbG9nZGlyIC92YXIvbG9nL2Nocm9ueQo=
            verification: {}
          filesystem: root
          mode: 420
          path: /etc/chrony.conf
    osImageURL: ""
  EOF
  ```

- 설정 적용

  ```bash
  oc apply -f ./masters-chrony-configuration.yaml
  oc apply -f ./workers-chrony-configuration.yaml
  ```
  



### 21. Infra Node Selecting

> OCP 4.x의 경우에는 초기에 Infra node가 worker node에 기본적으로 배포됩니다. 이를 설치 후에 infra 용도로 사용할 node를 지정하기 위해 node labels 작업과 resource를 옮기는 작업을 해야 합니다.

21-1) OCP Console 접속 (Cluster-admin 권한이 있는 사용자)

- Compute -> Nodes 선택 -> Edit Lables

  - 가이드에서는  [infra1.ocp.skt-poc.com](https://console-openshift-console.apps.ocp.skt-poc.com/k8s/cluster/nodes/infra1.ocp.skt-poc.com),  [infra2.ocp.skt-poc.com](https://console-openshift-console.apps.ocp.skbb-poc.com/k8s/cluster/nodes/infra1.ocp.skt-poc.com) Node를 Infra 용도로 만들어 두었기 때문에 해당 노드의 Labels를 변경 합니다.

    ```bash
    worekr -> infra
    ```

    - e.g) optional : router node가 따로 존재하는 경우 router node lables 추가

      ```bash
      worker -> router
      ```

  - Edit Labels 선택

    ```bash
    node-role.kubernetes.io/infra
    ```
  
    - e.g) optional : router node가 따로 존재하는 경우 
  
      ```bash
      node-role.kubernetes.io/router
      ```
  
    > 해당 부분을 추가 후 저장
  
  - 저장이 완료 되면, [infra1.ocp.skt-poc.com](https://console-openshift-console.apps.ocp.skt-poc.com/k8s/cluster/nodes/infra1.ocp.skt-poc.com),  [infra2.ocp.skt-poc.com](https://console-openshift-console.apps.ocp.skt-poc.com/k8s/cluster/nodes/infra1.ocp.skt-poc.com) 의 Role에 infra가 추가 된 것을 확인 할 수 있습니다.
  
  - worker node Lables 삭제
  
    ```bash
    node-role.kubernetes.io/worker
    ```
  
    > 저장 후 infra Lables만 남아 있는것 확인

21-2) Moving the router

> router node를 따로 구분하여 구성한 경우 ingressController Custom Resource는 router node에 적용합니다.

> router pod를 다른 node에 배포 할 수 있습니다. 기본적으로 해당 pod는 worker node에서 보여집니다.

- router Operator를 위한 ingressController Custom Resource 확인

  ```bash
  [root@bastion ocp]# oc get ingresscontroller default -n openshift-ingress-operator -o yaml
  apiVersion: operator.openshift.io/v1
  kind: IngressController
  metadata:
    creationTimestamp: "2020-04-08T03:01:56Z"
    finalizers:
    - ingresscontroller.operator.openshift.io/finalizer-ingresscontroller
    generation: 1
    name: default
    namespace: openshift-ingress-operator
    resourceVersion: "50616"
    selfLink: /apis/operator.openshift.io/v1/namespaces/openshift-ingress-operator/ingresscontrollers/default
    uid: ac6dde41-71e6-4829-9eac-a3b6ba28cfe3
  spec:
    replicas: 2
  status:
    availableReplicas: 2
    conditions:
    - lastTransitionTime: "2020-04-08T03:01:57Z"
      reason: Valid
      status: "True"
      type: Admitted
    - lastTransitionTime: "2020-04-08T04:58:57Z"
      status: "True"
      type: Available
    - lastTransitionTime: "2020-04-08T04:58:57Z"
      message: The deployment has Available status condition set to True
      reason: DeploymentAvailable
      status: "False"
      type: DeploymentDegraded
    - lastTransitionTime: "2020-04-08T03:02:17Z"
      message: The endpoint publishing strategy does not support a load balancer
      reason: UnsupportedEndpointPublishingStrategy
      status: "False"
      type: LoadBalancerManaged
    - lastTransitionTime: "2020-04-08T03:02:17Z"
      message: No DNS zones are defined in the cluster dns config.
      reason: NoDNSZones
      status: "False"
      type: DNSManaged
    - lastTransitionTime: "2020-04-08T04:58:57Z"
      status: "False"
      type: Degraded
    domain: apps.ocp.skt-poc.com
    endpointPublishingStrategy:
      type: HostNetwork
    observedGeneration: 1
    selector: ingresscontroller.operator.openshift.io/deployment-ingresscontroller=default
    tlsProfile:
      ciphers:
      - TLS_AES_128_GCM_SHA256
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
      - ECDHE-ECDSA-AES128-GCM-SHA256
      - ECDHE-RSA-AES128-GCM-SHA256
      - ECDHE-ECDSA-AES256-GCM-SHA384
      - ECDHE-RSA-AES256-GCM-SHA384
      - ECDHE-ECDSA-CHACHA20-POLY1305
      - ECDHE-RSA-CHACHA20-POLY1305
      - DHE-RSA-AES128-GCM-SHA256
      - DHE-RSA-AES256-GCM-SHA384
      minTLSVersion: VersionTLS12
  ```

- ingresscontroller resource와 nodeselector를 infra lable을 사용하여 변경합니다.

  ==방법은 yaml를 직접 수정하거나, patch command를 통해 적용 할 수 있습니다.==

  ```bash
  oc edit ingresscontroller default -n openshift-ingress-operator -o yaml
  ```

  - 방법1) 해당 yaml 파일 열어서 spec 부분에 다음을 추가

    - e.g) router node가 따로 존재하는 경우 아래 내용에서 `node-role.kubernetes.io/infra: ""` 대신 `node-role.kubernetes.io/router: ""`를 입력합니다.

    ```bash
      spec:
        nodePlacement:
          nodeSelector:
            matchLabels:
              node-role.kubernetes.io/router: ""
    ```

  - 방법2) patch command를 이용해서 적용

    - e.g) router node가 따로 존재하는 경우 아래 내용에서 `node-role.kubernetes.io/infra: ""` 대신 `node-role.kubernetes.io/router: ""`를 입력합니다.
    
    ```bash
    oc patch ingresscontroller default -n openshift-ingress-operator --type=merge --patch='{"spec":{"nodePlacement":{"nodeSelector": {"matchLabels":{"node-role.kubernetes.io/router":""}}}}}'
    ```

- 위의 두 가지 방법 중에 하나를 선택하여 적용하면 되고, 설정 후 router pod가 infra(router) node에 confirm 되었는지 확인

  ```bash
  [root@bastion ign]# oc get pod -n openshift-ingress -o wide
  NAME                              READY   STATUS    RESTARTS   AGE   IP             NODE                      NOMINATED NODE   READINESS GATES
  router-default-76499fcc6d-fwzvs   1/1     Running   0          34s   10.40.89.212   router2.ocp.skt-poc.com   <none>           <none>
  router-default-76499fcc6d-wbjn2   1/1     Running   0          59s   10.40.89.211   router1.ocp.skt-poc.com   <none>           <none>
  ```

- 위에서 확인한 infra node RUNNING상태 확인

  ```bash
  [root@bastion ign]# oc get node router1.ocp.skt-poc.com
  NAME                      STATUS   ROLES    AGE   VERSION
  router1.ocp.skt-poc.com   Ready    router   17m   v1.16.2
  [root@bastion ign]# oc get node router2.ocp.skt-poc.com
  NAME                      STATUS   ROLES    AGE   VERSION
  router2.ocp.skt-poc.com   Ready    router   17m   v1.16.2
  ```

21-3) Moving default registry

> registry resource를 infra node로 재 배치 합니다.

- patch command를 이용하여 적용

  ```bash
  oc patch configs.imageregistry.operator.openshift.io/cluster -n openshift-image-registry --type=merge --patch '{"spec":{"nodeSelector":{"node-role.kubernetes.io/infra":""}}}'
  ```

- 적용된 부분 확인

  ```bash
  oc get config/cluster -o yaml
  ```

  ```bash
  apiVersion: imageregistry.operator.openshift.io/v1
  kind: Config
  metadata:
    creationTimestamp: "2020-04-08T03:01:54Z"
    finalizers:
    - imageregistry.operator.openshift.io/finalizer
    generation: 4
    name: cluster
    resourceVersion: "88257"
    selfLink: /apis/imageregistry.operator.openshift.io/v1/configs/cluster
    uid: 236f6a0e-9dd1-4222-b082-06f233fc57fd
  spec:
    defaultRoute: false
    disableRedirect: false
    httpSecret: 775a7886ca2a5d62fc0fc15ad79b6bc4cd68645972daf7bc877a3506ef5f1be3d62f567830425a200e8853a01a6f02c66ab8b534c08f5a2943b32b002b2b33d1
    logging: 2
    managementState: Managed
    nodeSelector:
      node-role.kubernetes.io/infra: ""
  --- 생략 ---
  ```

20-4) Moving the monitoring solution

> 기본적으로 Prometheus, Grafana 및 AlertManager가 포함된 Prometheus 클러스터 모니터링 스택은 클러스터 모니터링을 제공하기 위해 배포됩니다. 클러스터 모니터링은 운영자가 관리합니다. 구성 요소를 다른 시스템으로 이동하려면 Custom Config Map을 작성하고 적용해야 합니다.

- Infra Node에 떠야 하는 구성 요소가 다른 Node에 예약되지 않도록 설정

  - Infra Node Taints 설정

    ```bash
    oc adm taint node infra1.ocp.skt-poc.com infra=reserved:NoSchedule
    oc adm taint node infra1.ocp.skt-poc.com infra=reserved:NoExecute
    
    oc adm taint node infra2.ocp.skt-poc.com infra=reserved:NoSchedule
    oc adm taint node infra2.ocp.skt-poc.com infra=reserved:NoExecute
    ```
    
    - e.g) router node가 따로 존재하는 경우 router node에도 Taints 설정을 해야 합니다.
    
  ```bash
  oc adm taint node router1.ocp.skt-poc.com router=reserved:NoSchedule
  oc adm taint node router1.ocp.skt-poc.com router=reserved:NoExecute
      
  oc adm taint node router2.ocp.skt-poc.com router=reserved:NoSchedule
  oc adm taint node router2.ocp.skt-poc.com router=reserved:NoExecute
  ```
  
  - ingress controller Node Taints 설정 (router node인 경우 router node에 적용)
  
    - e.g) router node가 따로 존재하는 경우 아래 내용에서 `node-role.kubernetes.io/infra: ""` 대신 `node-role.kubernetes.io/router: ""`를 입력합니다.
  
    ```bash
  oc patch ingresscontroller default -n openshift-ingress-operator --type=merge --patch='{"spec":{"nodePlacement": {"nodeSelector": {"matchLabels": {"node-role.kubernetes.io/router": ""}},"tolerations": [{"effect":"NoSchedule","key": "router","value": "reserved"},{"effect":"NoExecute","key": "router","value": "reserved"}]}}}'
    ```

  - Scheduler Operator Custom Resource를 ConfigMap에 추가 설정

    ```bash
    oc patch config cluster --type=merge --patch='{"spec":{"nodeSelector": {"node-role.kubernetes.io/infra": ""},"tolerations": [{"effect":"NoSchedule","key": "infra","value": "reserved"},{"effect":"NoExecute","key": "infra","value": "reserved"}]}}'
    ```

- cluster-monitoring-configmap.yaml  작성

  ```bash
  cat <<EOF>> monitoring.yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: cluster-monitoring-config
    namespace: openshift-monitoring
  data:
    config.yaml: |
      alertmanagerMain:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
      prometheusK8s:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
      prometheusOperator:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
      grafana:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
      k8sPrometheusAdapter:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
      kubeStateMetrics:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
      telemeterClient:
        nodeSelector:
          node-role.kubernetes.io/infra: ""
        tolerations:
        - key: infra
          value: reserved
          effect: NoSchedule
        - key: infra
          value: reserved
          effect: NoExecute
  EOF
  ```

- 적용

  ```bash
  [root@bastion ~]# oc create -f monitoring.yaml
  configmap/cluster-monitoring-config created
  ```

- 새로운 Machine으로 monitoring Pod가 이동 했는지 확인

  ```bash
  watch 'oc get pod -n openshift-monitoring -o wide'
  ```

  ```bash
  Every 2.0s: oc get pod -n openshift-monitoring -o wide                                                                                    Tue Feb 18 13:40:40 2020
  
  NAME                                           READY   STATUS    RESTARTS   AGE   IP              NODE                        NOMINATED NODE   READINESS GATES
  alertmanager-main-0                            3/3     Running   0          17s   10.130.0.27     infra1.ocp4.skbb-poc.com    <none>           <none>
  alertmanager-main-1                            3/3     Running   0          28s   10.130.0.26     infra1.ocp4.skbb-poc.com    <none>           <none>
  alertmanager-main-2                            3/3     Running   0          58s   10.130.2.12     infra2.ocp4.skbb-poc.com    <none>           <none>
  cluster-monitoring-operator-7bbc9f9895-d6jf7   1/1     Running   0          13h   10.128.0.28     master2.ocp4.skbb-poc.com   <none>           <none>
  grafana-565b7f4d9d-pw6nq                       2/2     Running   0          58s   10.130.2.11     infra2.ocp4.skbb-poc.com    <none>           <none>
  kube-state-metrics-f7df4b4fc-rbh8n             3/3     Running   0          79s   10.130.2.7      infra2.ocp4.skbb-poc.com    <none>           <none>
  node-exporter-5pd96                            2/2     Running   0          13h   10.76.168.142   master1.ocp4.skbb-poc.com   <none>           <none>
  node-exporter-927g4                            2/2     Running   0          13h   10.76.168.143   master2.ocp4.skbb-poc.com   <none>           <none>
  node-exporter-jd8rt                            2/2     Running   0          13h   10.76.168.145   infra1.ocp4.skbb-poc.com    <none>           <none>
  node-exporter-kpdmt                            2/2     Running   0          13h   10.76.168.146   infra2.ocp4.skbb-poc.com    <none>           <none>
  node-exporter-sqxzt                            2/2     Running   0          13h   10.76.168.148   worker2.ocp4.skbb-poc.com   <none>           <none>
  node-exporter-t9z7v                            2/2     Running   0          13h   10.76.168.144   master3.ocp4.skbb-poc.com   <none>           <none>
  node-exporter-v24lq                            2/2     Running   0          13h   10.76.168.147   worker1.ocp4.skbb-poc.com   <none>           <none>
  openshift-state-metrics-b6755756-89h7l         3/3     Running   0          13h   10.130.0.7      infra1.ocp4.skbb-poc.com    <none>           <none>
  prometheus-adapter-7594cf8dcd-7dvlk            1/1     Running   0          45s   10.130.0.25     infra1.ocp4.skbb-poc.com    <none>           <none>
  prometheus-adapter-7594cf8dcd-jpkhr            1/1     Running   0          64s   10.130.2.10     infra2.ocp4.skbb-poc.com    <none>           <none>
  prometheus-k8s-0                               7/7     Running   1          12h   10.130.0.24     infra1.ocp4.skbb-poc.com    <none>           <none>
  prometheus-k8s-1                               6/7     Running   1          38s   10.130.2.13     infra2.ocp4.skbb-poc.com    <none>           <none>
  prometheus-operator-6bf9c6f988-9w9t8           1/1     Running   0          79s   10.130.2.8      infra2.ocp4.skbb-poc.com    <none>           <none>
  telemeter-client-66fcbff8f5-pzjr9              3/3     Running   0          69s   10.130.2.9      infra2.ocp4.skbb-poc.com    <none>           <none>
  thanos-querier-684db5bccc-4gh5q                4/4     Running   0          12h   10.130.2.3      infra2.ocp4.skbb-poc.com    <none>           <none>
  thanos-querier-684db5bccc-sdrp2                4/4     Running   0          12h   10.129.0.36     master3.ocp4.skbb-poc.com   <none>           <none>
  ```

  > prometheus 관련 Pod가 infra node로 이동한 것을 확인 할 수 있습니다.
>또한, 위의 설정을 적용하면, infra node의 요소들이 다시 재 스케줄링 되면서 정리 됩니다.



==cluster-logging-operator-upgrade 수행 해야 함!!==


공식 문서 URL)

 https://access.redhat.com/documentation/en-us/openshift_container_platform/4.3/html/installing_on_vsphere/installing-on-vsphere#installation-initializing-manual_installing-vsphere 



 https://docs.openshift.com/container-platform/4.3/installing/install_config/installing-customizing.html 

