{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "oryn-audit-env";

  buildInputs = with pkgs; [
    coreutils 
    procps
    gnugrep
    gawk
    gnused
    util-linux
    shadow
    systemd
    nftables
    bind.dnsutils
    iproute2
    nix
    lshw
    pciutils
    usbutils
    dmidecode
    docker
    podman
    libvirt
    bc
    bat
    python3Packages.rich
  ];

  shellHook = ''
    echo -e "\033[1;31m
╔════════════════════════════════════╗
║    Welcome to OrynAudit Shell      ║
║  Your system is ready to confess   ║
╚════════════════════════════════════╝
\033[0m"
    echo -e "To begin: \033[1;32m./oryn_audit.sh\033[0m"
    if [ -f ./oryn_audit.sh ] && [ ! -x ./oryn_audit.sh ]; then
      echo -e "\033[1;33mWarning: oryn_audit.sh is not executable. Run: chmod +x ./oryn_audit.sh\033[0m"
    fi
  '';
}

