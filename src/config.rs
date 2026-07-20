use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "yatht",
    version,
    about = "Run a command with TCP and UDP traffic transparently proxied with seccomp user notification"
)]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub proxy: Option<String>,

    #[arg(long = "bypass-cidr")]
    pub bypass_cidrs: Vec<IpNet>,

    #[arg(long = "proxy-cidr")]
    pub proxy_cidrs: Vec<IpNet>,

    #[arg(long)]
    pub proxy_local: bool,

    #[arg(long)]
    pub connect_timeout: Option<String>,

    #[arg(long, help = "Redirect UDP/53 through DNS-over-TCP")]
    pub enable_dns: bool,

    #[arg(long, help = "Redirect generic UDP through SOCKS5 UDP ASSOCIATE")]
    pub enable_udp: bool,

    #[arg(long, help = "DNS-over-TCP upstream for --enable-dns")]
    pub dns_server: Option<String>,

    #[arg(long)]
    pub debug: bool,

    #[arg(last = true, required = true)]
    pub command: Vec<OsString>,
}

#[derive(Clone, Debug)]
pub struct EffectiveConfig {
    pub proxy: ProxyConfig,
    pub bypass_local: bool,
    pub bypass_cidrs: Vec<IpNet>,
    pub proxy_cidrs: Vec<IpNet>,
    pub connect_timeout: Duration,
    pub enable_dns: bool,
    pub enable_udp: bool,
    pub dns_server: String,
    pub debug: bool,
    pub command: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyConfig {
    Socks5 {
        addr: String,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        addr: String,
    },
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    proxy: Option<String>,
    connect_timeout: Option<String>,
    bypass_local: Option<bool>,
    bypass_cidrs: Option<Vec<IpNet>>,
    proxy_cidrs: Option<Vec<IpNet>>,
    enable_dns: Option<bool>,
    enable_udp: Option<bool>,
    dns_server: Option<String>,
    debug: Option<bool>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Route {
    Direct,
    Proxy,
}

impl EffectiveConfig {
    pub fn load(cli: Cli) -> Result<Self> {
        let file_cfg = match &cli.config {
            Some(path) => {
                let raw = fs::read_to_string(path)
                    .with_context(|| format!("read config {}", path.display()))?;
                toml::from_str::<FileConfig>(&raw)
                    .with_context(|| format!("parse config {}", path.display()))?
            }
            None => FileConfig::default(),
        };

        let proxy_raw = cli
            .proxy
            .or(file_cfg.proxy)
            .unwrap_or_else(|| "socks5://127.0.0.1:1080".to_string());
        let proxy = ProxyConfig::parse(&proxy_raw)?;

        let connect_timeout = match cli.connect_timeout.or(file_cfg.connect_timeout) {
            Some(s) => humantime::parse_duration(&s)
                .with_context(|| format!("parse connect timeout {s:?}"))?,
            None => Duration::from_secs(10),
        };

        let mut bypass_cidrs = file_cfg.bypass_cidrs.unwrap_or_default();
        bypass_cidrs.extend(cli.bypass_cidrs);

        let mut proxy_cidrs = file_cfg.proxy_cidrs.unwrap_or_default();
        proxy_cidrs.extend(cli.proxy_cidrs);

        let cfg = Self {
            proxy,
            bypass_local: if cli.proxy_local {
                false
            } else {
                file_cfg.bypass_local.unwrap_or(true)
            },
            bypass_cidrs,
            proxy_cidrs,
            connect_timeout,
            enable_dns: cli.enable_dns || file_cfg.enable_dns.unwrap_or(false),
            enable_udp: cli.enable_udp || file_cfg.enable_udp.unwrap_or(false),
            dns_server: cli
                .dns_server
                .or(file_cfg.dns_server)
                .unwrap_or_else(|| "1.1.1.1:53".to_string()),
            debug: cli.debug || file_cfg.debug.unwrap_or(false),
            command: cli.command,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.connect_timeout.is_zero() {
            bail!("connect timeout must be greater than zero");
        }
        if self.enable_udp && matches!(self.proxy, ProxyConfig::Http { .. }) {
            bail!("generic UDP redirection requires a SOCKS5 proxy");
        }
        if self.enable_dns {
            let mut addrs = self
                .dns_server
                .to_socket_addrs()
                .with_context(|| format!("resolve DNS server {:?}", self.dns_server))?;
            if !addrs.any(|addr| addr.port() != 0) {
                bail!(
                    "DNS server {:?} resolved to no address with a nonzero port",
                    self.dns_server
                );
            }
        }
        Ok(())
    }

    pub fn route_for(&self, ip: IpAddr) -> Route {
        if self.bypass_local && is_default_bypass(ip) {
            return Route::Direct;
        }
        if self.bypass_cidrs.iter().any(|net| net.contains(&ip)) {
            return Route::Direct;
        }
        if !self.proxy_cidrs.is_empty() && !self.proxy_cidrs.iter().any(|net| net.contains(&ip)) {
            return Route::Direct;
        }
        Route::Proxy
    }
}

impl ProxyConfig {
    pub fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).with_context(|| {
            format!("parse proxy URL {raw:?}; expected socks5://host:port or http://host:port")
        })?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("proxy URL is missing a host"))?;
        let port = url
            .port()
            .ok_or_else(|| anyhow!("proxy URL is missing a port"))?;
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            bail!("proxy URL must not contain a path, query, or fragment");
        }
        let addr = format_host_port(host, port);

        match url.scheme() {
            "socks5" | "socks5h" => {
                let username = if url.username().is_empty() {
                    None
                } else {
                    Some(url.username().to_string())
                };
                let password = url.password().map(ToOwned::to_owned);
                Ok(Self::Socks5 {
                    addr,
                    username,
                    password,
                })
            }
            "http" => {
                if !url.username().is_empty() || url.password().is_some() {
                    bail!("HTTP proxy authentication is not implemented in the first release");
                }
                Ok(Self::Http { addr })
            }
            other => bail!("unsupported proxy scheme {other:?}; use socks5:// or http://"),
        }
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn is_default_bypass(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_unique_local(ip)
                || is_ipv6_unicast_link_local(ip)
        }
    }
}

fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn parses_socks5_proxy() {
        let got = ProxyConfig::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(
            got,
            ProxyConfig::Socks5 {
                addr: "127.0.0.1:1080".to_string(),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
            }
        );
    }

    #[test]
    fn rejects_proxy_url_options_that_are_ignored() {
        let err = ProxyConfig::parse("socks5://127.0.0.1:1080/route?mode=tcp")
            .unwrap_err()
            .to_string();
        assert!(err.contains("path, query, or fragment"), "{err}");
    }

    #[test]
    fn rejects_unknown_file_config_fields() {
        let err = toml::from_str::<FileConfig>("proyx = 'socks5://127.0.0.1:1080'")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field `proyx`"), "{err}");
    }

    #[test]
    fn rejects_http_proxy_for_generic_udp() {
        let mut cfg = test_config();
        cfg.proxy = ProxyConfig::parse("http://127.0.0.1:8080").unwrap();
        cfg.enable_udp = true;

        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("requires a SOCKS5 proxy"), "{err}");
    }

    #[test]
    fn rejects_zero_connect_timeout() {
        let mut cfg = test_config();
        cfg.connect_timeout = Duration::ZERO;

        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("greater than zero"), "{err}");
    }

    #[test]
    fn rejects_invalid_dns_server_when_dns_is_enabled() {
        let mut cfg = test_config();
        cfg.enable_dns = true;
        cfg.dns_server = "invalid DNS server".to_string();

        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("resolve DNS server"), "{err}");
    }

    #[test]
    fn route_prefers_bypass_cidr() {
        let cfg = EffectiveConfig {
            proxy: ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap(),
            bypass_local: false,
            bypass_cidrs: vec![IpNet::from_str("203.0.113.0/24").unwrap()],
            proxy_cidrs: vec![],
            connect_timeout: Duration::from_secs(10),
            enable_dns: false,
            enable_udp: false,
            dns_server: "1.1.1.1:53".to_string(),
            debug: false,
            command: vec![OsString::from("true")],
        };

        assert_eq!(
            cfg.route_for(IpAddr::from_str("203.0.113.10").unwrap()),
            Route::Direct
        );
        assert_eq!(
            cfg.route_for(IpAddr::from_str("198.51.100.10").unwrap()),
            Route::Proxy
        );
    }

    #[test]
    fn proxy_cidr_is_allow_list() {
        let mut cfg = test_config();
        cfg.proxy_cidrs = vec![IpNet::from_str("198.51.100.0/24").unwrap()];

        assert_eq!(
            cfg.route_for(IpAddr::from_str("203.0.113.10").unwrap()),
            Route::Direct
        );
        assert_eq!(
            cfg.route_for(IpAddr::from_str("198.51.100.10").unwrap()),
            Route::Proxy
        );
    }

    fn test_config() -> EffectiveConfig {
        EffectiveConfig {
            proxy: ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap(),
            bypass_local: false,
            bypass_cidrs: vec![],
            proxy_cidrs: vec![],
            connect_timeout: Duration::from_secs(10),
            enable_dns: false,
            enable_udp: false,
            dns_server: "1.1.1.1:53".to_string(),
            debug: false,
            command: vec![OsString::from("true")],
        }
    }
}
