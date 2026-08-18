use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use url::Url;

/// Deprecated alias for `--udp-socket-mode`, kept for one release.
const UDP_SOCKET_MODE_ENV: &str = "SUP_UDP_SOCKET_MODE";

#[derive(Parser, Debug)]
#[command(
    name = "yatht",
    version,
    about = "Proxy TCP and experimental UDP for a trusted command with seccomp user notification"
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

    #[arg(
        long,
        help = "Experimental request/response UDP through SOCKS5 UDP ASSOCIATE"
    )]
    pub enable_udp: bool,

    #[arg(long, help = "DNS-over-TCP upstream for --enable-dns")]
    pub dns_server: Option<String>,

    #[arg(
        long,
        value_name = "MODE",
        help = "UDP socket identity model for --enable-udp [default: lazy]"
    )]
    pub udp_socket_mode: Option<UdpSocketMode>,

    #[arg(long)]
    pub debug: bool,

    #[arg(long, help = "Write experimental performance metrics as JSONL")]
    pub metrics_file: Option<PathBuf>,

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
    pub dns_server: Option<SocketAddr>,
    pub udp_socket_mode: UdpSocketMode,
    pub debug: bool,
    pub metrics_file: Option<PathBuf>,
    pub command: Vec<OsString>,
}

/// Socket identity model for redirected UDP. `Lazy` replaces the target's
/// descriptor on the first proxied send; `Stable` injects the relay endpoint at
/// `socket(2)` time so the open file description survives `dup(2)`, `fork(2)`,
/// and close races. Both change observable socket semantics, so the selector
/// lives on the CLI next to `--enable-udp` rather than in the data-plane
/// environment selectors.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum UdpSocketMode {
    #[default]
    Lazy,
    Stable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyConfig {
    Socks5 {
        endpoint: ProxyEndpoint,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        endpoint: ProxyEndpoint,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEndpoint {
    authority: String,
    addrs: Vec<SocketAddr>,
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
    udp_socket_mode: Option<UdpSocketMode>,
    debug: Option<bool>,
    metrics_file: Option<PathBuf>,
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

        let connect_timeout = match cli.connect_timeout.or(file_cfg.connect_timeout) {
            Some(s) => humantime::parse_duration(&s)
                .with_context(|| format!("parse connect timeout {s:?}"))?,
            None => Duration::from_secs(10),
        };
        if connect_timeout.is_zero() {
            bail!("connect timeout must be greater than zero");
        }

        let proxy_raw = cli
            .proxy
            .or(file_cfg.proxy)
            .unwrap_or_else(|| "socks5://127.0.0.1:1080".to_string());
        let mut proxy = ProxyConfig::parse(&proxy_raw)?;
        proxy.resolve(connect_timeout)?;

        let mut bypass_cidrs = file_cfg.bypass_cidrs.unwrap_or_default();
        bypass_cidrs.extend(cli.bypass_cidrs);

        let mut proxy_cidrs = file_cfg.proxy_cidrs.unwrap_or_default();
        proxy_cidrs.extend(cli.proxy_cidrs);

        let enable_dns = cli.enable_dns || file_cfg.enable_dns.unwrap_or(false);
        let dns_server_raw = cli
            .dns_server
            .or(file_cfg.dns_server)
            .unwrap_or_else(|| "1.1.1.1:53".to_string());
        let dns_server = enable_dns
            .then(|| resolve_dns_server(&dns_server_raw))
            .transpose()?;
        // Parsed even when an explicit flag or config key wins, so an
        // unsupported value keeps failing startup instead of being ignored.
        let env_udp_socket_mode = udp_socket_mode_from_env()?;

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
            enable_dns,
            enable_udp: cli.enable_udp || file_cfg.enable_udp.unwrap_or(false),
            dns_server,
            udp_socket_mode: cli
                .udp_socket_mode
                .or(file_cfg.udp_socket_mode)
                .or(env_udp_socket_mode)
                .unwrap_or_default(),
            debug: cli.debug || file_cfg.debug.unwrap_or(false),
            metrics_file: cli.metrics_file.or(file_cfg.metrics_file),
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
        if self.udp_socket_mode == UdpSocketMode::Stable && !self.enable_udp {
            bail!("--udp-socket-mode=stable requires --enable-udp");
        }
        Ok(())
    }

    pub fn route_for(&self, ip: IpAddr) -> Route {
        if self.bypass_local && is_default_bypass(ip) {
            return Route::Direct;
        }
        if self
            .bypass_cidrs
            .iter()
            .any(|net| route_net_contains(net, ip))
        {
            return Route::Direct;
        }
        if !self.proxy_cidrs.is_empty()
            && !self
                .proxy_cidrs
                .iter()
                .any(|net| route_net_contains(net, ip))
        {
            return Route::Direct;
        }
        Route::Proxy
    }
}

fn resolve_dns_server(raw: &str) -> Result<SocketAddr> {
    raw.to_socket_addrs()
        .with_context(|| format!("resolve DNS server {raw:?}"))?
        .find(|addr| addr.port() != 0)
        .ok_or_else(|| anyhow!("DNS server {raw:?} resolved to no address with a nonzero port"))
}

fn udp_socket_mode_from_env() -> Result<Option<UdpSocketMode>> {
    let raw = match std::env::var(UDP_SOCKET_MODE_ENV) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(err) => bail!("invalid {UDP_SOCKET_MODE_ENV} value: {err}"),
    };
    let mode = parse_udp_socket_mode_env(raw.as_deref())?;
    if mode.is_some() {
        eprintln!(
            "yatht: {UDP_SOCKET_MODE_ENV} is deprecated and will be removed; \
             use --udp-socket-mode instead"
        );
    }
    Ok(mode)
}

fn parse_udp_socket_mode_env(raw: Option<&str>) -> Result<Option<UdpSocketMode>> {
    raw.map(|raw| {
        UdpSocketMode::from_str(raw, false)
            .map_err(|_| anyhow!("unsupported {UDP_SOCKET_MODE_ENV} value: {raw}"))
    })
    .transpose()
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
        let endpoint = ProxyEndpoint::new(format_host_port(host, port));

        match url.scheme() {
            "socks5" | "socks5h" => {
                let username = if url.username().is_empty() {
                    None
                } else {
                    Some(decode_proxy_userinfo(url.username(), "username")?)
                };
                let password = url
                    .password()
                    .map(|password| decode_proxy_userinfo(password, "password"))
                    .transpose()?;
                validate_socks5_credentials(username.as_deref(), password.as_deref())?;
                Ok(Self::Socks5 {
                    endpoint,
                    username,
                    password,
                })
            }
            "http" => {
                if !url.username().is_empty() || url.password().is_some() {
                    bail!("HTTP proxy authentication is not implemented in the first release");
                }
                Ok(Self::Http { endpoint })
            }
            other => bail!("unsupported proxy scheme {other:?}; use socks5:// or http://"),
        }
    }

    pub fn endpoint(&self) -> &ProxyEndpoint {
        match self {
            Self::Socks5 { endpoint, .. } | Self::Http { endpoint } => endpoint,
        }
    }

    fn resolve(&mut self, timeout: Duration) -> Result<()> {
        let endpoint = match self {
            Self::Socks5 { endpoint, .. } | Self::Http { endpoint } => endpoint,
        };
        endpoint.resolve(timeout)
    }
}

fn decode_proxy_userinfo(raw: &str, field: &str) -> Result<String> {
    percent_decode_str(raw)
        .decode_utf8()
        .with_context(|| format!("SOCKS5 proxy {field} is not valid UTF-8 after URL decoding"))
        .map(|decoded| decoded.into_owned())
}

fn validate_socks5_credentials(username: Option<&str>, password: Option<&str>) -> Result<()> {
    if username.is_some_and(|value| value.len() > u8::MAX as usize)
        || password.is_some_and(|value| value.len() > u8::MAX as usize)
    {
        bail!("SOCKS5 username/password must be <= 255 bytes after URL decoding");
    }
    Ok(())
}

impl ProxyEndpoint {
    pub(crate) fn new(authority: String) -> Self {
        let addrs = authority.parse().into_iter().collect();
        Self { authority, addrs }
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    fn resolve(&mut self, timeout: Duration) -> Result<()> {
        if !self.addrs.is_empty() {
            return Ok(());
        }

        let authority = self.authority.clone();
        let resolver_authority = authority.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("yatht-proxy-resolver".to_string())
            .spawn(move || {
                let result = resolver_authority
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<_>>());
                let _ = tx.send(result);
            })
            .context("spawn proxy resolver")?;

        let addrs = match rx.recv_timeout(timeout) {
            Ok(result) => result.with_context(|| format!("resolve proxy {authority}"))?,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                bail!("resolving proxy {authority:?} exceeded {timeout:?}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("proxy resolver stopped before resolving {authority:?}")
            }
        };
        if addrs.is_empty() {
            bail!("proxy {authority:?} resolved to no addresses");
        }
        self.addrs = addrs;
        Ok(())
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
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_default_bypass(IpAddr::V4(mapped));
            }
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv6_unique_local(ip)
                || is_ipv6_unicast_link_local(ip)
        }
    }
}

fn route_net_contains(net: &IpNet, ip: IpAddr) -> bool {
    net.contains(&ip)
        || match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .is_some_and(|mapped| net.contains(&IpAddr::V4(mapped))),
            IpAddr::V4(_) => false,
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
                endpoint: ProxyEndpoint::new("127.0.0.1:1080".to_string()),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
            }
        );
    }

    #[test]
    fn decodes_socks5_proxy_credentials() {
        let got = ProxyConfig::parse("socks5://us%65r:p%40ss%3Aword%2Ftwo@127.0.0.1:1080").unwrap();

        assert!(matches!(
            got,
            ProxyConfig::Socks5 {
                username: Some(ref username),
                password: Some(ref password),
                ..
            } if username == "user" && password == "p@ss:word/two"
        ));
    }

    #[test]
    fn rejects_invalid_or_oversized_decoded_credentials() {
        let invalid = ProxyConfig::parse("socks5://user:%FF@127.0.0.1:1080")
            .unwrap_err()
            .to_string();
        assert!(invalid.contains("not valid UTF-8"), "{invalid}");

        let oversized = format!("socks5://{}:pass@127.0.0.1:1080", "x".repeat(256));
        let oversized = ProxyConfig::parse(&oversized).unwrap_err().to_string();
        assert!(oversized.contains("<= 255 bytes"), "{oversized}");
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
    fn rejects_stable_udp_socket_mode_without_generic_udp() {
        let mut cfg = test_config();
        cfg.udp_socket_mode = UdpSocketMode::Stable;

        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("requires --enable-udp"), "{err}");

        cfg.enable_udp = true;
        cfg.validate().unwrap();
    }

    #[test]
    fn accepts_lazy_udp_socket_mode_without_generic_udp() {
        let mut cfg = test_config();
        cfg.udp_socket_mode = UdpSocketMode::Lazy;

        cfg.validate().unwrap();
    }

    #[test]
    fn parses_udp_socket_mode_flag_values() {
        let cli =
            Cli::try_parse_from(["yatht", "--udp-socket-mode", "stable", "--", "true"]).unwrap();
        assert_eq!(cli.udp_socket_mode, Some(UdpSocketMode::Stable));

        let cli = Cli::try_parse_from(["yatht", "--udp-socket-mode=lazy", "--", "true"]).unwrap();
        assert_eq!(cli.udp_socket_mode, Some(UdpSocketMode::Lazy));

        let cli = Cli::try_parse_from(["yatht", "--", "true"]).unwrap();
        assert_eq!(cli.udp_socket_mode, None);

        let err = Cli::try_parse_from(["yatht", "--udp-socket-mode", "eager", "--", "true"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("eager"), "{err}");
    }

    #[test]
    fn parses_udp_socket_mode_from_the_config_file() {
        let file_cfg = toml::from_str::<FileConfig>("udp_socket_mode = 'stable'").unwrap();
        assert_eq!(file_cfg.udp_socket_mode, Some(UdpSocketMode::Stable));

        let err = toml::from_str::<FileConfig>("udp_socket_mode = 'eager'")
            .unwrap_err()
            .to_string();
        assert!(err.contains("eager"), "{err}");
    }

    #[test]
    fn accepts_the_deprecated_udp_socket_mode_env_alias() {
        assert_eq!(parse_udp_socket_mode_env(None).unwrap(), None);
        assert_eq!(
            parse_udp_socket_mode_env(Some("lazy")).unwrap(),
            Some(UdpSocketMode::Lazy)
        );
        assert_eq!(
            parse_udp_socket_mode_env(Some("stable")).unwrap(),
            Some(UdpSocketMode::Stable)
        );
    }

    #[test]
    fn rejects_unsupported_udp_socket_mode_env_alias_values() {
        let err = parse_udp_socket_mode_env(Some("Stable"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unsupported SUP_UDP_SOCKET_MODE value"),
            "{err}"
        );

        let err = parse_udp_socket_mode_env(Some("")).unwrap_err().to_string();
        assert!(
            err.contains("unsupported SUP_UDP_SOCKET_MODE value"),
            "{err}"
        );
    }

    #[test]
    fn resolves_and_caches_proxy_hostname_addresses() {
        let mut endpoint = ProxyEndpoint::new("localhost:1080".to_string());
        assert!(endpoint.addrs().is_empty());

        endpoint.resolve(Duration::from_secs(2)).unwrap();

        assert!(!endpoint.addrs().is_empty());
        assert!(endpoint.addrs().iter().all(|addr| addr.port() == 1080));
    }

    #[test]
    fn rejects_invalid_dns_server_when_dns_is_enabled() {
        let err = resolve_dns_server("invalid DNS server")
            .unwrap_err()
            .to_string();
        assert!(err.contains("resolve DNS server"), "{err}");
    }

    #[test]
    fn resolves_dns_server_to_a_nonzero_port() {
        assert_eq!(
            resolve_dns_server("127.0.0.1:53").unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53))
        );
        assert!(resolve_dns_server("127.0.0.1:0").is_err());
    }

    #[test]
    fn load_stores_resolved_dns_server() {
        let cli = Cli {
            config: None,
            proxy: None,
            bypass_cidrs: Vec::new(),
            proxy_cidrs: Vec::new(),
            proxy_local: false,
            connect_timeout: None,
            enable_dns: true,
            enable_udp: false,
            dns_server: Some("127.0.0.1:5353".to_string()),
            udp_socket_mode: None,
            debug: false,
            metrics_file: None,
            command: vec![OsString::from("true")],
        };

        let cfg = EffectiveConfig::load(cli).unwrap();

        assert_eq!(
            cfg.dns_server,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 5353)))
        );
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
            dns_server: None,
            udp_socket_mode: UdpSocketMode::Lazy,
            debug: false,
            metrics_file: None,
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

    #[test]
    fn mapped_ipv4_uses_default_bypass_classification() {
        let mut cfg = test_config();
        cfg.bypass_local = true;

        assert_eq!(
            cfg.route_for(IpAddr::from_str("::ffff:127.0.0.1").unwrap()),
            Route::Direct
        );
        assert_eq!(
            cfg.route_for(IpAddr::from_str("::ffff:10.1.2.3").unwrap()),
            Route::Direct
        );
        assert_eq!(
            cfg.route_for(IpAddr::from_str("::ffff:203.0.113.10").unwrap()),
            Route::Proxy
        );
    }

    #[test]
    fn mapped_ipv4_matches_ipv4_cidr_rules() {
        let mut cfg = test_config();
        cfg.bypass_cidrs = vec![IpNet::from_str("203.0.113.0/24").unwrap()];
        assert_eq!(
            cfg.route_for(IpAddr::from_str("::ffff:203.0.113.10").unwrap()),
            Route::Direct
        );

        cfg.bypass_cidrs.clear();
        cfg.proxy_cidrs = vec![IpNet::from_str("198.51.100.0/24").unwrap()];
        assert_eq!(
            cfg.route_for(IpAddr::from_str("::ffff:198.51.100.10").unwrap()),
            Route::Proxy
        );
        assert_eq!(
            cfg.route_for(IpAddr::from_str("::ffff:203.0.113.10").unwrap()),
            Route::Direct
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
            dns_server: None,
            udp_socket_mode: UdpSocketMode::Lazy,
            debug: false,
            metrics_file: None,
            command: vec![OsString::from("true")],
        }
    }
}
