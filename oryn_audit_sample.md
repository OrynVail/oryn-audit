# OrynAudit Report

**Generated:** 2025-05-24 14:24:12
**Host:** #####
**User:** root
**Kernel:** ###
**NixOS Version:** 24.11.### (Vicuna)
**NixOS Generation:** 124 (Path: /nix/store/####)

---

## Dependency Check

- **✅ GOOD:** All critical dependencies met.
- **🔵 INFO:** Missing optional tools: nixos-version-list. Some checks may be skipped or limited.
**INFO:** Missing optional tools: nixos-version-list. Some checks may be skipped or limited.

## System Information


```
Gathering basic system details...
```


### Basic System Info

- **Hostname:** ######
- **Kernel Version:** #####
- **Operating System:** NixOS 24.11 (Vicuna)
- **NixOS Version:** 24.11.### (Vicuna)
- **NixOS Generation:** 124 (Path: /nix/store/#####)
- **System Uptime:** N/A (or 'uptime -p' produced no output)
- **Current Load Average:** 0.39, 0.44, 0.44
- **✅ GOOD:** Basic system information collected.

### Memory Usage

**Memory Details:**

```
               total        used        free      shared  buff/cache   available
Mem:            31Gi       3.7Gi        22Gi       649Mi       6.3Gi        27Gi
Swap:          8.0Gi          0B       8.0Gi
```

- **🔵 INFO:** Memory Usage: 3.7Gi / 31Gi
- **🔵 INFO:** Swap Usage: 0B / 8.0Gi
- **Swap:** 0B / 8.0Gi

### Disk Usage

**Filesystem Mounts and Usage:**

```
Filesystem     Type      Size  Used Avail Use% Mounted on
devtmpfs       devtmpfs  1.6G     0  1.6G   0% /dev
/dev/nvme1n1p3 btrfs     924G   28G  889G   3% /
efivarfs       efivarfs  248K  153K   91K  63% /sys/firmware/efi/efivars
/dev/nvme1n1p1 vfat      511M   34M  478M   7% /boot
```

- **✅ GOOD:** Disk usage OK: / (btrfs) is 3% full (28G/924G).
- **✅ GOOD:** Disk usage OK: /boot (vfat) is 7% full (34M/511M).

## NixOS Specific Checks

- **✅ GOOD:** NixOS detected: 24.11.### (Vicuna)
Performing NixOS-specific security and configuration checks.

### NixOS Configuration

- **🔵 INFO:** NixOS configuration file /etc/nixos/configuration.nix not found. (May be in a non-standard path)
- **Configuration file:** /etc/nixos/configuration.nix not found (may be in a non-standard path)

### Nix Channel Status

- **🔵 INFO:** Nix channels configured for root:
**Nix Channels for root:**

```
nixos https://nixos.org/channels/nixos-24.11
```


### Nix Store Integrity

- **🔵 INFO:** Nix store command is available. For a full integrity check, consider running 'sudo nix-store --verify --check-contents' (can be very slow).
**Nix Store:** 'nix-store' available. Full verification is a manual, time-consuming step.
- **🔴 HIGH:** Security issue: Writable paths found in Nix store
- **Nix Store Permissions:** SECURITY ISSUE - Writable paths found

```
/nix/store/####
/nix/store/####
/nix/store/####
```


### Nix Daemon Status

- **✅ GOOD:** nix-daemon service is active
- **Nix Daemon:** Active

### NixOS Kernel Hardening

**Kernel Hardening Parameters:**
- **🟡 MEDIUM:** Kernel parameter kernel.kptr_restrict set to 1 (expected: 2)
- **kernel.kptr_restrict:** 1 ❌ (expected: 2)
- **🟡 MEDIUM:** Kernel parameter kernel.sysrq set to 16 (expected: 0)
- **kernel.sysrq:** 16 ❌ (expected: 0)
- **🟡 MEDIUM:** Kernel parameter kernel.unprivileged_bpf_disabled set to 2 (expected: 1)
- **kernel.unprivileged_bpf_disabled:** 2 ❌ (expected: 1)
- **🔵 INFO:** Kernel parameter kernel.unprivileged_userns_clone not available
- **kernel.unprivileged_userns_clone:** Not available
- **✅ GOOD:** Kernel parameter kernel.dmesg_restrict correctly set to 1
- **kernel.dmesg_restrict:** 1 ✅

## Network Security


### Network Interfaces

**Network Interfaces:**

```
lo               UNKNOWN        127.#.#.#/8 
enp44s0          UP             192.###.#.##/24 
wlp0s20f3        DOWN           
```

- **🟡 MEDIUM:** Interfaces in promiscuous mode detected (potential security risk)
**Interfaces in Promiscuous Mode:**

```
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 allmulti 0 minmtu 0 maxmtu 0 addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536 
    link/ether ##:##:##:##:##:## brd ff:ff:ff:ff:ff:ff promiscuity 0 allmulti 0 minmtu 68 maxmtu 9194 addrgenmode none numtxqueues 1 numrxqueues 1 gso_max_size 64000 gso_max_segs 64 tso_max_size 64000 tso_max_segs 64 gro_max_size 65536 gso_ipv4_max_size 64000 gro_ipv4_max_size 65536 parentbus pci parentdev 0000:##:##.0 
    link/ether ##:##:##:##:##:## brd ff:ff:ff:ff:ff:ff permaddr ##:##:##:##:##:## promiscuity 0 allmulti 0 minmtu 256 maxmtu 2304 addrgenmode none numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 gso_ipv4_max_size 65536 gro_ipv4_max_size 65536 parentbus pci parentdev 0000:##:##.3 
```


### Open Listening Ports

**TCP Listening Ports:**

```
LISTEN 0      5          127.#.#.#:##      0.0.0.0:*    users:((".ulauncher-wrap",pid=2497,fd=16))
LISTEN 0      4096      127.#.#.#:##        0.0.0.0:*    users:(("systemd-resolve",pid=999,fd=20)) 
LISTEN 0      4096   127.#.#.##:##        0.0.0.0:*    users:(("systemd-resolve",pid=999,fd=18)) 
LISTEN 0      4096         #.#.#.#:####      0.0.0.0:*    users:(("systemd-resolve",pid=999,fd=12)) 
```

- **🔵 INFO:** Service on port #### (N/A)
- **✅ GOOD:** Standard service on port ## (N/A)
- **✅ GOOD:** Standard service on port ## (N/A)
- **🔵 INFO:** Service on port #### (N/A)
**UDP Listening Ports:**

```
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                                   
UNCONN 0      0            #.#.#.#:####       0.0.0.0:*    users:(("avahi-daemon",pid=###,fd=11))  
UNCONN 0      0            #.#.#.#:####       0.0.0.0:*    users:(("systemd-resolve",pid=###,fd=13))
UNCONN 0      0            #.#.#.#:####       0.0.0.0:*    users:(("systemd-resolve",pid=###,fd=11))
UNCONN 0      0            #.#.#.#:#####      0.0.0.0:*    users:(("avahi-daemon",pid=###,fd=12))  
UNCONN 0      0            #.#.#.#:#####      0.0.0.0:*    users:(("###-bin",pid=###,fd=109))  
UNCONN 0      0         127.#.#.##:##         0.0.0.0:*    users:(("systemd-resolve",pid=###,fd=19))
UNCONN 0      0      127.#.#.###:##         0.0.0.0:*    users:(("systemd-resolve",pid=###,fd=17))
UNCONN 0      0            0.#.#.#:####      0.0.0.0:*    users:(("###-bin",pid=###,fd=194))  
```

- **🔵 INFO:** UDP service on port #### (N/A)
- **🔵 INFO:** UDP service on port #### (N/A)
- **🔵 INFO:** UDP service on port #### (N/A)
- **🔵 INFO:** UDP service on port #### (N/A)
- **🔵 INFO:** UDP service on port ##### (N/A)
- **🔵 INFO:** UDP service on port ## (N/A)
- **🔵 INFO:** UDP service on port ## (N/A)
- **🔵 INFO:** UDP service on port ##### (N/A)

### Firewall Status

**NFTables Ruleset:**
- **✅ GOOD:** NFTables rules active (2 rules)

```
table ip filter {
	chain nixos-fw-accept {
		counter packets 174574 bytes 210281129 accept
	}

	chain nixos-fw-refuse {
		counter packets 5576 bytes 787518 drop
	}

	chain nixos-fw-log-refuse {
		tcp flags & (fin | syn | rst | ack) == syn counter packets 0 bytes 0 log prefix "refused connection: " level info
		pkttype != unicast counter packets 5576 bytes 787518 jump nixos-fw-refuse
		counter packets 0 bytes 0 jump nixos-fw-refuse
	}

	chain nixos-fw {
		iifname "lo" counter packets 241 bytes 26991 jump nixos-fw-accept
		ct state related,established counter packets 170383 bytes 209550131 jump nixos-fw-accept
		udp dport 5353 counter packets 3950 bytes 704007 jump nixos-fw-accept
		ip protocol icmp icmp type echo-request counter packets 0 bytes 0 jump nixos-fw-accept
```

*(Showing first 20 lines of ruleset)*

### DNS Configuration

**DNS Servers:**

```
127.#.#.###
```

- **🟡 MEDIUM:** Using potentially public or ISP DNS server: 127.#.#.##

### DNS Leak Test

**DNS Leak Test Results:**
- IP as seen by OpenDNS resolver1: 117.###.###.##
- IP as seen by system's default resolver: 
- **🟡 MEDIUM:** DNS leak test inconclusive (could not fetch IPs)

### SSH Configuration

- **🔵 INFO:** SSH server configuration file not found

## File System Security


### SUID/SGID Files

**SUID Root Files:**
- **✅ GOOD:** No SUID root files found in main filesystem areas
No SUID root files found in main filesystem areas (excluding /proc, /sys, /dev, /run)
**SGID Files (Sample):**
- **✅ GOOD:** No SGID files found in sample
No SGID files found in sample (checked up to 10)

### World-Writable Files

**World-Writable Files (Sample):**
- **✅ GOOD:** No world-writable files found in sampled locations
No world-writable files found in main filesystem areas (excluding /proc, /sys, /dev, /run, /nix/store)

### Unowned Files

**Unowned/Ungrouped Files (Sample):**
- **✅ GOOD:** No unowned/ungrouped files found in sampled locations
No unowned/ungrouped files found in main filesystem areas (excluding /proc, /sys, /dev, /run, /nix/store)

### Suspicious Hidden Files

**Suspicious Hidden Files in Home Directories (Sample):**
- **✅ GOOD:** No suspicious large hidden files found in home directories
No suspicious large hidden files found in home directories

## User Account Security


### Users with Login Shells

**Users with Login Shells:**
- **🔴 HIGH:** Root account: root (UID: ##, Shell: /run/current-system/sw/bin/bash)
- **ROOT:** root (UID: 0, Shell: /run/current-system/sw/bin/bash)
- **🔵 INFO:** User account: ###### (UID: ####, Shell: /run/current-system/sw/bin/zsh)
- **USER:** ###### (UID: 1000, Shell: /run/current-system/sw/bin/zsh)

### Password Policy

**Password Policy Settings:**

### Sudo Privileges

**Sudo Configuration:**
- **🟡 MEDIUM:** Users/groups with full sudo privileges found
**Users/groups with full sudo privileges:**

```
/etc/sudoers:root     ALL=(ALL:ALL)    SETENV: ALL
/etc/sudoers:%wheel  ALL=(ALL:ALL)    NOPASSWD:SETENV: ALL
```

- **🔴 HIGH:** NOPASSWD sudo entries found (allows sudo without password)
**NOPASSWD sudo entries (security risk):**

```
/etc/sudoers:%wheel  ALL=(ALL:ALL)    NOPASSWD:SETENV: ALL
```


## Process Security


### Processes Running as Root

**Root Processes (Top CPU Usage):**
- PID 1: /run/current-system/systemd/lib/systemd/systemd  (CPU: 1.2%)
- **🔵 INFO:** Root process: /run/####/systemd  (CPU: 1.2%)
- PID 1063: /nix/store/#####  (CPU: 1.1%)
- **🔵 INFO:** Root process: /nix/store/#####  (CPU: 1.1%)
- PID 1089: /nix/store/##### (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/##### (CPU: 0.0%)
- PID 620: /nix/store/##### (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/##### (CPU: 0.0%)
- PID 9175: bash /home/#####  (CPU: 0.0%)
- **🔵 INFO:** Root process: bash /home/#####  (CPU: 0.0%)
- PID 1696: /nix/store/#####  (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/##### (CPU: 0.0%)
- PID 1048: /nix/store/#####--foreground --netlink --confdir /nix/store/##### (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/#### --foreground --netlink --confdir /nix/store/#####  (CPU: 0.0%)
- PID 658: /nix/store/#####  (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/#####  (CPU: 0.0%)
- PID 2552: /nix/store/#####  (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/##### (CPU: 0.0%)
- PID 1890: /nix/store/#####--no-daemon  (CPU: 0.0%)
- **🔵 INFO:** Root process: /nix/store/##### --no-daemon  (CPU: 0.0%)

### Unusual Process Check

**Unusual Processes:**
- **🔴 HIGH:** Processes running from unusual locations detected
Processes running from unusual locations:

```
####        ####  0.3  0.0  #####  7168 pts/0    S    14:23   0:01 bash --rcfile /tmp/nix-shell-####-0/rc
```

- **✅ GOOD:** No processes with deleted binaries
No processes with deleted binaries detected

### Cron Jobs

**Scheduled Tasks:**
- **🔵 INFO:** Systemd timers found
Systemd timers:

```
NEXT                            LEFT LAST                           PASSED UNIT                         ACTIVATES
Sat 2025-05-24 15:00:00 IST    30min Sat 2025-05-24 14:00:06 IST 29min ago logrotate.timer              logrotate.service
Sun 2025-05-25 03:15:00 IST      12h Sat 2025-05-24 10:11:36 IST         - nix-gc.timer                 nix-gc.service
Sun 2025-05-25 13:33:20 IST      23h Sat 2025-05-24 13:33:20 IST 56min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2025-05-26 00:19:15 IST 1 day 9h Mon 2025-05-19 19:00:18 IST         - fstrim.timer                 fstrim.service

4 timers listed.
Pass --all to see loaded but inactive timers, too.
```


## Container and Virtualization Security


### Docker Security

**Docker Environment Check:**
- **🔵 INFO:** Docker installed
Docker is installed on this system.
- **🔵 INFO:** Docker installed but daemon not running
Docker is installed but the daemon is not running.

### Podman Security

**Podman Environment Check:**
- **🔵 INFO:** Podman installed
Podman is installed on this system.
- **🔵 INFO:** Podman version: 5.2.3
- Podman version: 5.2.3
- **🔵 INFO:** No Podman containers running
- No running containers

### Virtualization Check

**Virtualization Environment:**
- **🔵 INFO:** System appears to be running on bare metal
This system appears to be running on bare metal (not virtualized).

## Hardware Security


### CPU Information

**CPU Details:**

```
Architecture:                         x86_64
CPU op-mode(s):                       32-bit, 64-bit
Address sizes:                        ####
Byte Order:                           Little Endian
CPU(s):                               16
On-line CPU(s) list:                  0-15
Vendor ID:                            #####
BIOS Vendor ID:                       #####
Model name:                           ####
BIOS Model name:                      ##### O.E.M. CPU @ 2.2GHz
BIOS CPU family:                      ####
CPU family:                           6
Model:                                141
Thread(s) per core:                   2
Core(s) per socket:                   8
```

- **🔵 INFO:** Checking CPU security vulnerabilities
**CPU Vulnerabilities:**
- gather_data_sampling: Mitigation: Microcode
- **🟡 MEDIUM:** CPU vulnerability gather_data_sampling mitigated: Mitigation: Microcode
- itlb_multihit: Not affected
- **✅ GOOD:** CPU not vulnerable to itlb_multihit: Not affected
- l1tf: Not affected
- **✅ GOOD:** CPU not vulnerable to l1tf: Not affected
- mds: Not affected
- **✅ GOOD:** CPU not vulnerable to mds: Not affected
- meltdown: Not affected
- **✅ GOOD:** CPU not vulnerable to meltdown: Not affected
- mmio_stale_data: Not affected
- **✅ GOOD:** CPU not vulnerable to mmio_stale_data: Not affected
- reg_file_data_sampling: Not affected
- **✅ GOOD:** CPU not vulnerable to reg_file_data_sampling: Not affected
- retbleed: Not affected
- **✅ GOOD:** CPU not vulnerable to retbleed: Not affected
- spec_rstack_overflow: Not affected
- **✅ GOOD:** CPU not vulnerable to spec_rstack_overflow: Not affected
- spec_store_bypass: Mitigation: Speculative Store Bypass disabled via prctl
- **🟡 MEDIUM:** CPU vulnerability spec_store_bypass mitigated: Mitigation: Speculative Store Bypass disabled via prctl
- spectre_v1: Mitigation: usercopy/swapgs barriers and __user pointer sanitization
- **🟡 MEDIUM:** CPU vulnerability spectre_v1 mitigated: Mitigation: usercopy/swapgs barriers and __user pointer sanitization
- spectre_v2: Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; PBRSB-eIBRS: SW sequence; BHI: SW loop, KVM: SW loop
- **🟡 MEDIUM:** CPU vulnerability spectre_v2 mitigated: Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; PBRSB-eIBRS: SW sequence; BHI: SW loop, KVM: SW loop
- srbds: Not affected
- **✅ GOOD:** CPU not vulnerable to srbds: Not affected
- tsx_async_abort: Not affected
- **✅ GOOD:** CPU not vulnerable to tsx_async_abort: Not affected

### PCI Devices

**PCI Devices:**

```
0000:00:00.0 Host bridge: #### Host Bridge/DRAM Registers (rev 05)
0000:00:01.0 PCI bridge: #### PCIe Controller #1 (rev 05)
0000:00:02.0 VGA compatible controller: #### [UHD Graphics] (rev 01)
0000:00:04.0 Signal processing controller: #### Dynamic Tuning Processor Participant (rev 05)
0000:00:06.0 System peripheral: ####Managed Controller
0000:00:07.0 PCI bridge: ####PCI Express Root Port #0 (rev 05)
0000:00:08.0 System peripheral: Intel Corporation GNA Scoring Accelerator module (rev 05)
0000:00:0d.0 USB controller: ####Controller (rev 05)
0000:00:0d.2 USB controller: ####NHI #0 (rev 05)
0000:00:0e.0 RAID bus controller: ####NVMe RAID Controller
```

*(Showing first 10 PCI devices)*
- **🟡 MEDIUM:** Wireless network device detected
- Wireless network device detected

### USB Devices

**USB Devices:**

```
Bus 001 Device 001: ID 1d6b:#### #### 2.0 root hub
Bus 002 Device 001: ID 1d6b:#### #### 3.0 root hub
Bus 002 Device 002: ID 0bda:#### #### Corp. Hub
Bus 003 Device 001: ID 1d6b:#### #### 2.0 root hub
Bus 003 Device 002: ID 0bda:#### #### R#### Hub
Bus 003 Device 003: ID 04f2:#### ####Ltd HD User Facing
Bus 003 Device 005: ID 8087:#### #### Bluetooth
Bus 003 Device 007: ID 046d:#### #### Receiver
Bus 003 Device 008: ID 258a:#### SINO WEALTH Bluetooth Keyboard
Bus 004 Device 001: ID 1d6b:#### ###root hub
```

- **🔵 INFO:** 10 USB devices detected

### Storage Devices

**Storage Devices:**

```
NAME          SIZE TYPE MOUNTPOINT FSTYPE
sda         931.5G disk            
└─sda1      931.5G part            ntfs
nvme0n1     476.9G disk            
├─nvme0n1p1   200M part            vfat
├─nvme0n1p2    16M part            
├─nvme0n1p3 475.6G part            ntfs
└─nvme0n1p4   1.1G part            ntfs
nvme1n1     931.5G disk            
├─nvme1n1p1   512M part /boot      vfat
├─nvme1n1p2     8G part [SWAP]     swap
└─nvme1n1p3   923G part /nix/store btrfs
```

- **🟡 MEDIUM:** Unencrypted swap partition detected
- Unencrypted swap partition detected
- **🟡 MEDIUM:** No encrypted storage detected
- No encrypted storage detected

## Package Security


### NixOS Packages

**NixOS Package Information:**
- **🔵 INFO:** 1 packages installed via nix-env
- 1 packages installed via nix-env
**Sample of Installed Packages:**

```

```

- **🔵 INFO:** Checking for outdated packages (may take a moment)...
- **✅ GOOD:** No outdated packages detected
- No outdated packages detected

### System Packages

**System Package Information:**
- **🔵 INFO:** Current system path: /nix/store/####
- Current system path: /nix/store/####
- **🔵 INFO:** System contains approximately ### packages/dependencies
- System contains approximately ### packages/dependencies
- **✅ GOOD:** No non-Nix package managers found
- No non-Nix package managers found

## Startup Services Analysis


### Enabled Services

**Enabled Services:**

```
accounts-daemon.service                  enabled ignored
acpid.service                            enabled ignored
audit.service                            enabled ignored
avahi-daemon.service                     enabled ignored
bluetooth.service                        enabled ignored
firewall.service                         enabled ignored
generate-shutdown-ramfs.service          enabled ignored
home-manager-oryn.service                enabled ignored
kmod-static-nodes.service                enabled ignored
logrotate-checkconf.service              enabled ignored
ModemManager.service                     enabled ignored
mount-pstore.service                     enabled ignored
network-local-commands.service           enabled ignored
NetworkManager-dispatcher.service        enabled ignored
NetworkManager.service                   enabled ignored
nscd.service                             enabled ignored
pre-sleep.service                        enabled ignored
prepare-kexec.service                    enabled ignored
reload-systemd-vconsole-setup.service    enabled ignored
save-hwclock.service                     enabled ignored
```

*(Showing first 20 enabled services)*
- **🔵 INFO:** Enabled service: accounts-daemon.service
- **🔵 INFO:** Enabled service: acpid.service
- **🔵 INFO:** Enabled service: audit.service
- **🔵 INFO:** Enabled service: avahi-daemon.service
- **🔵 INFO:** Enabled service: bluetooth.service
- **🔵 INFO:** Enabled service: firewall.service
- **🔵 INFO:** Enabled service: generate-shutdown-ramfs.service
- **🔵 INFO:** Enabled service: home-manager-oryn.service
- **🔵 INFO:** Enabled service: kmod-static-nodes.service
- **🔵 INFO:** Enabled service: logrotate-checkconf.service
- **🔵 INFO:** Enabled service: ModemManager.service
- **🔵 INFO:** Enabled service: mount-pstore.service
- **🔵 INFO:** Enabled service: network-local-commands.service
- **🔵 INFO:** Enabled service: NetworkManager-dispatcher.service
- **🔵 INFO:** Enabled service: NetworkManager.service
- **🔵 INFO:** Enabled service: nscd.service
- **🔵 INFO:** Enabled service: pre-sleep.service
- **🔵 INFO:** Enabled service: prepare-kexec.service
- **🔵 INFO:** Enabled service: reload-systemd-vconsole-setup.service
- **🔵 INFO:** Enabled service: save-hwclock.service
- **🔵 INFO:** Enabled service: suid-sgid-wrappers.service
- **✅ GOOD:** Essential service: systemd-boot-random-seed.service
- **✅ GOOD:** Essential service: systemd-hibernate-clear.service
- **✅ GOOD:** Essential service: systemd-journal-catalog-update.service
- **✅ GOOD:** Essential service: systemd-journal-flush.service
- **✅ GOOD:** Essential service: systemd-journald.service
- **✅ GOOD:** Essential service: systemd-logind.service
- **✅ GOOD:** Essential service: systemd-machine-id-commit.service
- **✅ GOOD:** Essential service: systemd-modules-load.service
- **✅ GOOD:** Essential service: systemd-oomd.service
- **✅ GOOD:** Essential service: systemd-pstore.service
- **✅ GOOD:** Essential service: systemd-random-seed.service
- **✅ GOOD:** Essential service: systemd-resolved.service
- **✅ GOOD:** Essential service: systemd-sysctl.service
- **✅ GOOD:** Essential service: systemd-timesyncd.service
- **✅ GOOD:** Essential service: systemd-tmpfiles-resetup.service
- **✅ GOOD:** Essential service: systemd-tmpfiles-setup-dev-early.service
- **✅ GOOD:** Essential service: systemd-tmpfiles-setup-dev.service
- **✅ GOOD:** Essential service: systemd-tmpfiles-setup.service
- **✅ GOOD:** Essential service: systemd-tpm2-setup-early.service
- **✅ GOOD:** Essential service: systemd-tpm2-setup.service
- **✅ GOOD:** Essential service: systemd-udev-trigger.service
- **✅ GOOD:** Essential service: systemd-udevd.service
- **✅ GOOD:** Essential service: systemd-update-done.service
- **✅ GOOD:** Essential service: systemd-update-utmp.service
- **✅ GOOD:** Essential service: systemd-user-sessions.service
- **🔵 INFO:** Enabled service: 46

### Failed Services

**Failed Services:**
- **✅ GOOD:** No failed services
No failed services found

### Socket Units

**Active Sockets:**

```
  avahi-daemon.socket             loaded active running   #### Activation Socket
  dbus.socket                     loaded active running   #### Bus Socket
  nix-daemon.socket               loaded active running   ####
  systemd-bootctl.socket          loaded active listening #### Socket
  systemd-coredump.socket         loaded active listening #### Socket
  systemd-creds.socket            loaded active listening Credential Encryption/Decryption
  systemd-hostnamed.socket        loaded active listening Hostname Service Socket
  systemd-journald-audit.socket   loaded active running   Journal Audit Socket
  systemd-journald-dev-log.socket loaded active running   Journal Socket (/dev/log)
  systemd-journald.socket         loaded active running   Journal Sockets
```

*(Showing first 10 active sockets)*
- **🔵 INFO:** 15 active socket units

## Log Analysis


### Authentication Failures

**Recent Authentication Failures:**
- **✅ GOOD:** No recent authentication failures detected
No recent authentication failures detected

### System Errors

**Recent System Errors:**

```
May 24 13:18:18 ####kernel: ACPI Error: Aborting method \AFUB._STA due to previous error (AE_AML_REGION_LIMIT) (20230628/psparse-529)
May 24 13:18:18 ####kernel: ACPI Error: 
May 24 13:18:18 ####kernel: ACPI Error: Aborting method \AFUB._STA due to previous error (AE_AML_REGION_LIMIT) (20230628/psparse-529)
May 24 13:18:18 ####kernel: ACPI Error: Field [AFU0] Base+Offset+Width 512+0+1 is beyond end of region [COMP] (length 512) (20230628/exfldio-163)
May 24 13:18:18 ####kernel: ACPI Error: Aborting method \AFUB._STA due to previous error (AE_AML_REGION_LIMIT) (20230628/psparse-529)
May 24 13:18:18 ####kernel: ACPI Error: Field [AFU0] Base+Offset+Width 512+0+1 is beyond end of region [COMP] (length 512) (20230628/exfldio-163)
May 24 13:18:18 ####kernel: ACPI Error: Aborting method \AFUB._STA due to previous error (AE_AML_REGION_LIMIT) (20230628/psparse-529)
May 24 13:18:21 ####bluetoothd[1051]: Failed to set mode: Failed (0x03)
May 24 13:18:38 ####gdm-password][2099]: gkr-pam: unable to locate daemon control file
May 24 13:18:39 ####systemd[2118]: Failed to start Application launched by gnome-session-binary.
```

- **🔵 INFO:** 10 recent system errors detected

### Login History

**Recent Logins:**

```
#####     tty2         tty2             Sat May 24 13:18   still logged in
#####     seat0        login screen     Sat May 24 13:18   still logged in
#####     tty2                          Sat May 24 13:18 - 13:18  (00:00)
#####   system boot  6.6.89           Sat May 24 13:18   still running
#####     tty2         tty2             Sat May 24 10:11 - 11:35  (01:23)
#####     seat0        login screen     Sat May 24 10:11 - down   (01:23)
#####     tty2                          Sat May 24 10:11 - 10:11  (00:00)
#####   system boot  6.6.89           Sat May 24 10:11 - 11:35  (01:23)
#####     tty2         tty2             Fri May 23 19:16 - 23:35  (04:18)
#####     seat0        login screen     Fri May 23 19:16 - down   (04:18)

wtmp begins Sun Apr 27 16:45:09 2025
```

- **🟡 MEDIUM:** Remote logins detected
**Remote Logins Detected:**

```
#####     tty2         tty2             Sat May 24 13:18   still logged in
#####     seat0        login screen     Sat May 24 13:18   still logged in
#####     tty2                          Sat May 24 13:18 - 13:18  (00:00)
#####   system boot  6.6.89           Sat May 24 13:18   still running
#####     tty2         tty2             Sat May 24 10:11 - 11:35  (01:23)
#####     seat0        login screen     Sat May 24 10:11 - down   (01:23)
#####     tty2                          Sat May 24 10:11 - 10:11  (00:00)
#####   system boot  6.6.89           Sat May 24 10:11 - 11:35  (01:23)
#####     tty2         tty2             Fri May 23 19:16 - 23:35  (04:18)
#####     seat0        login screen     Fri May 23 19:16 - down   (04:18)
wtmp begins Sun Apr 27 16:45:09 2025
```


## OrynAudit Summary

- **✅ GOOD:** Audit completed successfully.
- **🔵 INFO:** Full report saved to: /tmp/oryn_audit-20250524-142412.md

**Findings Summary:**
- ✅ Good Practices Confirmed: 27
- 🔴 High Priority Issues: 3
- 🟡 Medium Priority Issues: 14
- 🔵 Informational Findings: 24
