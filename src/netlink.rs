//! A minimal rtnetlink client: just the requests capsule needs to wire up a
//! container's network (what `ip link`, `ip addr` and `ip route` send).

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

use libc::c_int;

use crate::sys;

/// From `<linux/veth.h>`, which libc doesn't cover.
const VETH_INFO_PEER: u16 = 1;

/// `struct rtmsg` from `<linux/rtnetlink.h>`, which libc doesn't cover.
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32,
}

/// Netlink pads every header and attribute to 4 bytes.
const fn align(len: usize) -> usize {
    (len + 3) & !3
}

const NLMSG_HDRLEN: usize = align(mem::size_of::<libc::nlmsghdr>());
const RTA_HDRLEN: usize = align(mem::size_of::<libc::rtattr>());

/// Builds one netlink request: `nlmsghdr`, a fixed family header, then attributes.
struct Message {
    buf: Vec<u8>,
    /// Offsets of nested attributes still open, whose lengths are backfilled.
    open: Vec<usize>,
}

impl Message {
    fn new<T: Copy>(kind: u16, flags: c_int, header: &T) -> Message {
        let nlmsghdr = libc::nlmsghdr {
            nlmsg_len: 0, // set by finish()
            nlmsg_type: kind,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK | flags) as u16,
            nlmsg_seq: 0, // set by finish()
            nlmsg_pid: 0, // the kernel
        };
        let mut msg = Message {
            buf: Vec::new(),
            open: Vec::new(),
        };
        msg.push_struct(&nlmsghdr);
        msg.push_struct(header);
        msg
    }

    fn attr(&mut self, kind: u16, data: &[u8]) -> &mut Message {
        let len = (RTA_HDRLEN + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
        self
    }

    fn attr_str(&mut self, kind: u16, value: &str) -> &mut Message {
        let mut data = value.as_bytes().to_vec();
        data.push(0);
        self.attr(kind, &data)
    }

    fn attr_u32(&mut self, kind: u16, value: u32) -> &mut Message {
        self.attr(kind, &value.to_ne_bytes())
    }

    fn attr_ipv4(&mut self, kind: u16, addr: Ipv4Addr) -> &mut Message {
        self.attr(kind, &addr.octets())
    }

    /// Open an attribute whose payload is everything until `end_nested`.
    fn begin_nested(&mut self, kind: u16) -> &mut Message {
        self.open.push(self.buf.len());
        self.attr(kind, &[])
    }

    fn end_nested(&mut self) -> &mut Message {
        let start = self.open.pop().expect("end_nested without begin_nested");
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    /// Append `value`'s bytes. Only for `#[repr(C)]` netlink headers whose
    /// every byte is initialised: no implicit padding between or after fields.
    fn push_struct<T: Copy>(&mut self, value: &T) {
        // SAFETY: `value` is a valid T for size_of::<T>() bytes, and callers only
        // pass padding-free repr(C) structs, so every byte read is initialised.
        let bytes = unsafe {
            std::slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>())
        };
        self.buf.extend_from_slice(bytes);
        self.pad();
    }

    fn pad(&mut self) {
        self.buf.resize(align(self.buf.len()), 0);
    }

    fn finish(mut self, seq: u32) -> Vec<u8> {
        assert!(self.open.is_empty(), "unclosed nested attribute");
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }
}

fn ifinfomsg(index: u32) -> libc::ifinfomsg {
    // SAFETY: ifinfomsg is plain integers, for which all-zero is valid; zeroed()
    // also covers its private padding field.
    let mut info: libc::ifinfomsg = unsafe { mem::zeroed() };
    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = index as c_int;
    info
}

fn bridge_message(name: &str) -> Message {
    let mut msg = Message::new(
        libc::RTM_NEWLINK,
        libc::NLM_F_CREATE | libc::NLM_F_EXCL,
        &ifinfomsg(0),
    );
    msg.attr_str(libc::IFLA_IFNAME, name)
        .begin_nested(libc::IFLA_LINKINFO)
        .attr_str(libc::IFLA_INFO_KIND, "bridge")
        .end_nested();
    msg
}

fn veth_message(name: &str, peer: &str, peer_pid: u32) -> Message {
    let mut msg = Message::new(
        libc::RTM_NEWLINK,
        libc::NLM_F_CREATE | libc::NLM_F_EXCL,
        &ifinfomsg(0),
    );
    msg.attr_str(libc::IFLA_IFNAME, name)
        .begin_nested(libc::IFLA_LINKINFO)
        .attr_str(libc::IFLA_INFO_KIND, "veth")
        .begin_nested(libc::IFLA_INFO_DATA)
        .begin_nested(VETH_INFO_PEER);
    // The peer is described like a whole link: its own ifinfomsg, then attributes.
    msg.push_struct(&ifinfomsg(0));
    msg.attr_str(libc::IFLA_IFNAME, peer)
        .attr_u32(libc::IFLA_NET_NS_PID, peer_pid)
        .end_nested()
        .end_nested()
        .end_nested();
    msg
}

pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Netlink> {
        // The kernel binds the socket to an address on first send, so no bind().
        let fd = sys::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )?;
        Ok(Netlink { fd, seq: 0 })
    }

    /// `ip link add NAME type bridge`
    pub fn create_bridge(&mut self, name: &str) -> io::Result<()> {
        self.request(bridge_message(name))
    }

    /// `ip link add NAME type veth peer name PEER netns PEER_PID`
    pub fn create_veth(&mut self, name: &str, peer: &str, peer_pid: u32) -> io::Result<()> {
        self.request(veth_message(name, peer, peer_pid))
    }

    /// `ip link set dev INDEX master MASTER`
    pub fn set_master(&mut self, index: u32, master: u32) -> io::Result<()> {
        let mut msg = Message::new(libc::RTM_NEWLINK, 0, &ifinfomsg(index));
        msg.attr_u32(libc::IFLA_MASTER, master);
        self.request(msg)
    }

    /// `ip link set dev INDEX up`
    pub fn set_up(&mut self, index: u32) -> io::Result<()> {
        let mut info = ifinfomsg(index);
        info.ifi_flags = libc::IFF_UP as u32;
        info.ifi_change = libc::IFF_UP as u32;
        self.request(Message::new(libc::RTM_NEWLINK, 0, &info))
    }

    /// `ip addr add ADDR/PREFIX dev INDEX`
    pub fn add_addr(&mut self, index: u32, addr: Ipv4Addr, prefix: u8) -> io::Result<()> {
        let header = libc::ifaddrmsg {
            ifa_family: libc::AF_INET as u8,
            ifa_prefixlen: prefix,
            ifa_flags: 0,
            ifa_scope: libc::RT_SCOPE_UNIVERSE,
            ifa_index: index,
        };
        let mut msg = Message::new(
            libc::RTM_NEWADDR,
            libc::NLM_F_CREATE | libc::NLM_F_EXCL,
            &header,
        );
        msg.attr_ipv4(libc::IFA_LOCAL, addr)
            .attr_ipv4(libc::IFA_ADDRESS, addr);
        self.request(msg)
    }

    /// `ip route add default via GATEWAY`
    pub fn add_default_route(&mut self, gateway: Ipv4Addr) -> io::Result<()> {
        let header = RtMsg {
            family: libc::AF_INET as u8,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: libc::RT_TABLE_MAIN,
            protocol: libc::RTPROT_BOOT,
            scope: libc::RT_SCOPE_UNIVERSE,
            kind: libc::RTN_UNICAST,
            flags: 0,
        };
        let mut msg = Message::new(
            libc::RTM_NEWROUTE,
            libc::NLM_F_CREATE | libc::NLM_F_EXCL,
            &header,
        );
        msg.attr_ipv4(libc::RTA_GATEWAY, gateway);
        self.request(msg)
    }

    /// Send one request and wait for the kernel's ack (an `NLMSG_ERROR` whose
    /// error is 0) or its errno.
    fn request(&mut self, msg: Message) -> io::Result<()> {
        self.seq += 1;
        let buf = msg.finish(self.seq);

        sys::send(&self.fd, &buf)?;

        let mut reply = [0u8; 8192];
        loop {
            let len = match sys::recv(&self.fd, &mut reply) {
                Ok(len) => len,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if let Some(result) = find_ack(&reply[..len], self.seq) {
                return result;
            }
        }
    }
}

/// Scan a datagram of netlink messages for the ack to request `seq`.
fn find_ack(mut data: &[u8], seq: u32) -> Option<io::Result<()>> {
    let u32_at = |d: &[u8], at: usize| u32::from_ne_bytes(d[at..at + 4].try_into().unwrap());
    let u16_at = |d: &[u8], at: usize| u16::from_ne_bytes(d[at..at + 2].try_into().unwrap());

    while data.len() >= NLMSG_HDRLEN {
        let len = u32_at(data, 0) as usize;
        if len < NLMSG_HDRLEN || len > data.len() {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed netlink reply",
            )));
        }
        let kind = u16_at(data, 4) as c_int;
        if kind == libc::NLMSG_ERROR && u32_at(data, 8) == seq && len >= NLMSG_HDRLEN + 4 {
            // nlmsgerr.error: 0 for an ack, otherwise a negated errno.
            let error =
                i32::from_ne_bytes(data[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap());
            return Some(match error {
                0 => Ok(()),
                e => Err(io::Error::from_raw_os_error(-e)),
            });
        }
        data = &data[align(len).min(data.len())..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(buf: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes(buf[at..at + 2].try_into().unwrap())
    }

    fn u32_at(buf: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap())
    }

    /// A message with an empty 4-byte family header, so attributes start at 20.
    fn empty() -> Message {
        Message::new(libc::RTM_NEWLINK, 0, &0u32)
    }

    const ATTRS: usize = NLMSG_HDRLEN + 4;

    #[test]
    fn header_fields() {
        let buf = empty().finish(7);
        assert_eq!(buf.len(), ATTRS);
        assert_eq!(u32_at(&buf, 0), ATTRS as u32);
        assert_eq!(u16_at(&buf, 4), libc::RTM_NEWLINK);
        assert_eq!(
            u16_at(&buf, 6),
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16
        );
        assert_eq!(u32_at(&buf, 8), 7);
    }

    #[test]
    fn attribute_is_padded_to_four_bytes() {
        let mut msg = empty();
        msg.attr_str(libc::IFLA_IFNAME, "ab");
        let buf = msg.finish(1);
        // rta_len counts the 4-byte header and "ab\0", but not the padding.
        assert_eq!(u16_at(&buf, ATTRS), 7);
        assert_eq!(u16_at(&buf, ATTRS + 2), libc::IFLA_IFNAME);
        assert_eq!(&buf[ATTRS + 4..ATTRS + 8], b"ab\0\0");
        assert_eq!(buf.len(), ATTRS + 8);
    }

    #[test]
    fn nested_attribute_length_covers_children() {
        let mut msg = empty();
        msg.begin_nested(libc::IFLA_LINKINFO)
            .attr_str(libc::IFLA_INFO_KIND, "veth")
            .end_nested();
        let buf = msg.finish(1);
        // 4 (nest header) + 4 (child header) + 5 ("veth\0") padded to 8.
        assert_eq!(u16_at(&buf, ATTRS), 16);
        assert_eq!(u16_at(&buf, ATTRS + 4), 9);
        assert_eq!(buf.len(), ATTRS + 16);
    }

    #[test]
    fn veth_message_layout() {
        let buf = veth_message("vcap1", "eth0", 42).finish(3);
        assert_eq!(u32_at(&buf, 0) as usize, buf.len());
        let flags = u16_at(&buf, 6) as c_int;
        assert_ne!(flags & libc::NLM_F_CREATE, 0);
        assert_ne!(flags & libc::NLM_F_EXCL, 0);

        let mut at = NLMSG_HDRLEN + mem::size_of::<libc::ifinfomsg>();
        assert_eq!(u16_at(&buf, at + 2), libc::IFLA_IFNAME);
        assert_eq!(&buf[at + 4..at + 10], b"vcap1\0");
        at += align(u16_at(&buf, at) as usize);

        // LINKINFO runs to the end of the message.
        assert_eq!(u16_at(&buf, at + 2), libc::IFLA_LINKINFO);
        assert_eq!(at + u16_at(&buf, at) as usize, buf.len());

        // The peer's netns pid is the last attribute.
        let pid_attr = buf.len() - 8;
        assert_eq!(u16_at(&buf, pid_attr + 2), libc::IFLA_NET_NS_PID);
        assert_eq!(u32_at(&buf, pid_attr + 4), 42);
    }

    fn ack(seq: u32, error: i32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((NLMSG_HDRLEN + 4 + NLMSG_HDRLEN) as u32).to_ne_bytes());
        buf.extend_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&error.to_ne_bytes());
        buf.resize(NLMSG_HDRLEN + 4 + NLMSG_HDRLEN, 0);
        buf
    }

    /// The errno of `find_ack`'s answer: Some(0) for an ack, None for no answer.
    fn ack_errno(data: &[u8], seq: u32) -> Option<i32> {
        find_ack(data, seq).map(|result| match result {
            Ok(()) => 0,
            Err(e) => e.raw_os_error().expect("an OS error"),
        })
    }

    #[test]
    fn find_ack_reads_errno() {
        assert_eq!(ack_errno(&ack(5, 0), 5), Some(0));
        assert_eq!(ack_errno(&ack(5, -libc::EEXIST), 5), Some(libc::EEXIST));
        assert_eq!(ack_errno(&ack(4, 0), 5), None, "other request's ack");
        let mut two = ack(4, 0);
        two.extend(ack(5, -libc::EPERM));
        assert_eq!(ack_errno(&two, 5), Some(libc::EPERM));
    }
}
