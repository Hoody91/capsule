use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::errno::Errno;
use nix::net::if_::if_nametoindex;
use nix::unistd::Pid;

use crate::container::Error;
use crate::netlink::Netlink;

const BRIDGE: &str = "capsule0";
const BRIDGE_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
const PREFIX: u8 = 24;
const SUBNET: &str = "10.200.0.0/24";

/// Name of the container's end of the veth pair, inside its namespace.
const CONTAINER_IF: &str = "eth0";

const RUN_DIR: &str = "/run/capsule";
const HOST_RESOLV_CONF: &str = "/etc/resolv.conf";
const FALLBACK_NAMESERVER: &str = "1.1.1.1";

/// Masquerade traffic leaving the subnet for anywhere but the bridge itself.
/// The flush makes re-applying it on every run leave exactly one rule.
const NAT_RULESET: &str = r#"
add table ip capsule
flush table ip capsule
add chain ip capsule postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule ip capsule postrouting ip saddr 10.200.0.0/24 oifname != "capsule0" masquerade
"#;

/// Host-side state for one bridged container. Dropping it releases the
/// address lease and removes the generated files.
pub struct Network {
    pub addr: Ipv4Addr,
    lease: PathBuf,
    dir: PathBuf,
}

impl Network {
    /// Prepare the host (bridge, forwarding, NAT), lease an address, and write
    /// the container's resolv.conf and hosts. Runs before the child exists.
    pub fn setup_host(hostname: &str) -> Result<Network, Error> {
        let mut nl = Netlink::open().map_err(netlink("opening netlink socket"))?;
        ensure_bridge(&mut nl)?;
        enable_forwarding()?;
        apply_nat()?;

        let run_dir = Path::new(RUN_DIR);
        let (addr, lease) = lease_address(&run_dir.join("ips"))?;
        let network = Network {
            addr,
            lease,
            dir: run_dir.join(std::process::id().to_string()),
        };

        fs::create_dir_all(&network.dir).map_err(io_error(&network.dir))?;
        let host_resolv = fs::read_to_string(HOST_RESOLV_CONF).unwrap_or_default();
        write(
            &network.dir.join("resolv.conf"),
            &container_resolv_conf(&host_resolv),
        )?;
        write(&network.dir.join("hosts"), &container_hosts(addr, hostname))?;

        Ok(network)
    }

    /// Give the child `pid` a veth pair: `eth0` in its namespace, and a host
    /// end on the bridge. The kernel deletes both when the namespace dies.
    pub fn attach(&self, pid: Pid) -> Result<(), Error> {
        let host_if = format!("vcap{pid}");
        let mut nl = Netlink::open().map_err(netlink("opening netlink socket"))?;
        nl.create_veth(&host_if, CONTAINER_IF, pid.as_raw() as u32)
            .map_err(netlink("creating veth pair"))?;
        let index = index_of(&host_if)?;
        nl.set_master(index, index_of(BRIDGE)?)
            .map_err(netlink("attaching veth to bridge"))?;
        nl.set_up(index).map_err(netlink("bringing up veth"))
    }

    /// Files to bind-mount read-only over the rootfs's, as (host, container).
    pub fn bind_mounts(&self) -> Vec<(PathBuf, &'static str)> {
        vec![
            (self.dir.join("resolv.conf"), "/etc/resolv.conf"),
            (self.dir.join("hosts"), "/etc/hosts"),
        ]
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for result in [fs::remove_dir_all(&self.dir), fs::remove_file(&self.lease)] {
            if let Err(e) = result {
                eprintln!("capsule: cleaning up network state: {e}");
            }
        }
    }
}

/// Runs in the child's new network namespace, after the parent has attached
/// the veth pair: bring up loopback and, if bridged, `eth0` with its address
/// and a default route through the bridge.
pub fn configure(addr: Option<Ipv4Addr>) -> Result<(), Error> {
    let mut nl = Netlink::open().map_err(netlink("opening netlink socket"))?;
    nl.set_up(index_of("lo")?)
        .map_err(netlink("bringing up lo"))?;

    if let Some(addr) = addr {
        let index = index_of(CONTAINER_IF)?;
        nl.add_addr(index, addr, PREFIX)
            .map_err(netlink("adding address to eth0"))?;
        nl.set_up(index).map_err(netlink("bringing up eth0"))?;
        nl.add_default_route(BRIDGE_ADDR)
            .map_err(netlink("adding default route"))?;
    }
    Ok(())
}

/// Create the bridge with its gateway address, tolerating a previous run's.
fn ensure_bridge(nl: &mut Netlink) -> Result<(), Error> {
    ignore_exists(nl.create_bridge(BRIDGE)).map_err(netlink("creating bridge capsule0"))?;
    let index = index_of(BRIDGE)?;
    ignore_exists(nl.add_addr(index, BRIDGE_ADDR, PREFIX))
        .map_err(netlink("adding address to capsule0"))?;
    nl.set_up(index).map_err(netlink("bringing up capsule0"))
}

fn enable_forwarding() -> Result<(), Error> {
    let path = Path::new("/proc/sys/net/ipv4/ip_forward");
    fs::write(path, "1").map_err(io_error(path))
}

fn apply_nat() -> Result<(), Error> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Nft(format!("running nft: {e} (is nftables installed?)")))?;

    let mut stdin = child.stdin.take().expect("stdin is piped");
    let written = stdin.write_all(NAT_RULESET.as_bytes());
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|e| Error::Nft(format!("running nft: {e}")))?;
    written.map_err(|e| Error::Nft(format!("writing ruleset to nft: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Nft(format!(
            "applying NAT for {SUBNET}: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// Claim a free address in the subnet by creating `dir/<addr>` holding our
/// pid. Leases whose pid no longer exists are left over from a crash and are
/// reclaimed.
fn lease_address(dir: &Path) -> Result<(Ipv4Addr, PathBuf), Error> {
    fs::create_dir_all(dir).map_err(io_error(dir))?;
    let [a, b, c, _] = BRIDGE_ADDR.octets();

    for host in 2..=254 {
        let addr = Ipv4Addr::new(a, b, c, host);
        let path = dir.join(addr.to_string());
        if try_lease(&path)? {
            return Ok((addr, path));
        }
        if lease_is_stale(&path) {
            let _ = fs::remove_file(&path);
            if try_lease(&path)? {
                return Ok((addr, path));
            }
        }
    }
    Err(Error::NoFreeAddress)
}

/// Atomically create the lease file. False if someone already holds it.
fn try_lease(path: &Path) -> Result<bool, Error> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            write!(file, "{}", std::process::id()).map_err(io_error(path))?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(io_error(path)(e)),
    }
}

fn lease_is_stale(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(pid) => match pid.trim().parse::<u32>() {
            Ok(pid) => !Path::new(&format!("/proc/{pid}")).exists(),
            // Still being written by its creator, or garbage; leave it.
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// The host's resolv.conf, minus nameservers the container can't reach:
/// loopback ones (they'd mean the container's own loopback) and IPv6 (the
/// container has no IPv6 route).
fn container_resolv_conf(host: &str) -> String {
    let mut out = String::new();
    let mut nameservers = 0;
    for line in host.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("nameserver"), Some(addr)) => {
                if let Ok(IpAddr::V4(addr)) = addr.parse::<IpAddr>()
                    && !addr.is_loopback()
                {
                    out.push_str(&format!("nameserver {addr}\n"));
                    nameservers += 1;
                }
            }
            (Some("search" | "domain" | "options"), Some(_)) => {
                out.push_str(line.trim());
                out.push('\n');
            }
            _ => {}
        }
    }
    if nameservers == 0 {
        out.push_str(&format!("nameserver {FALLBACK_NAMESERVER}\n"));
    }
    out
}

fn container_hosts(addr: Ipv4Addr, hostname: &str) -> String {
    format!("127.0.0.1\tlocalhost\n::1\tlocalhost\n{addr}\t{hostname}\n")
}

fn index_of(name: &str) -> Result<u32, Error> {
    if_nametoindex(name).map_err(netlink("looking up interface index"))
}

fn ignore_exists(result: Result<(), Errno>) -> Result<(), Errno> {
    match result {
        Err(Errno::EEXIST) => Ok(()),
        other => other,
    }
}

fn write(path: &Path, contents: &str) -> Result<(), Error> {
    fs::write(path, contents).map_err(io_error(path))
}

fn netlink(op: &'static str) -> impl Fn(Errno) -> Error {
    move |source| Error::Netlink { op, source }
}

fn io_error(path: &Path) -> impl Fn(io::Error) -> Error {
    let path = path.to_path_buf();
    move |source| Error::Network {
        path: path.clone(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_keeps_reachable_nameservers() {
        let host = "# generated by WSL\n\
                    nameserver 10.255.255.254\n\
                    nameserver 127.0.0.53\n\
                    nameserver ::1\n\
                    nameserver 2001:4860:4860::8888\n\
                    search lan\n\
                    options edns0\n";
        assert_eq!(
            container_resolv_conf(host),
            "nameserver 10.255.255.254\nsearch lan\noptions edns0\n"
        );
    }

    #[test]
    fn resolv_conf_falls_back_without_usable_nameservers() {
        assert_eq!(
            container_resolv_conf("nameserver 127.0.0.53\n"),
            "nameserver 1.1.1.1\n"
        );
        assert_eq!(container_resolv_conf(""), "nameserver 1.1.1.1\n");
    }

    #[test]
    fn hosts_maps_hostname_to_container_address() {
        let hosts = container_hosts(Ipv4Addr::new(10, 200, 0, 7), "box");
        assert!(hosts.contains("127.0.0.1\tlocalhost\n"));
        assert!(hosts.ends_with("10.200.0.7\tbox\n"));
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("capsule-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn leases_are_unique_and_reclaimed_when_stale() {
        let dir = scratch_dir("lease");

        let (first, _) = lease_address(&dir).unwrap();
        let (second, _) = lease_address(&dir).unwrap();
        assert_eq!(first, Ipv4Addr::new(10, 200, 0, 2));
        assert_eq!(second, Ipv4Addr::new(10, 200, 0, 3));

        // A lease held by a pid that doesn't exist is free to take.
        fs::write(dir.join("10.200.0.2"), "4294967295").unwrap();
        let (reclaimed, _) = lease_address(&dir).unwrap();
        assert_eq!(reclaimed, first);

        fs::remove_dir_all(&dir).unwrap();
    }
}
