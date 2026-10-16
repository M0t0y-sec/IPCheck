//! CLI front end for the same core the GUI uses.
//!
//! Exists so the engine can be verified, scripted, and diffed without a window
//! in the way. When the card shows something surprising, this is how you find
//! out whether the engine or the rendering is at fault.
//!
//!   ipcheck                 probe this machine and human-print the result
//!   ipcheck --json          machine-readable snapshot on stdout
//!   ipcheck --ip 1.2.3.4    look up a specific address instead of the egress
//!   ipcheck --watch         refresh every 60s, printing only changes

use ipcheck_lib::{aggregator, Config};

/// Minimal argument parsing. A CLI this small does not justify a dependency,
/// and adding one to a tool that handles network identity is the wrong trade.
struct Args {
    json: bool,
    ip: Option<String>,
    watch: Option<u64>,
    no_sources: bool,
    help: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        json: false,
        ip: None,
        watch: None,
        no_sources: false,
        help: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" | "-j" => a.json = true,
            "--ip" | "-i" => a.ip = it.next(),
            "--watch" | "-w" => {
                a.watch = Some(
                    it.next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(60),
                )
            }
            "--no-sources" => a.no_sources = true,
            "--help" | "-h" => a.help = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    a
}

fn print_help() {
    println!(
        "ipcheck-cli {} — IP intelligence probe

USAGE:
    ipcheck-cli [OPTIONS]

OPTIONS:
    -j, --json            emit the full snapshot as JSON
    -i, --ip <ADDR>       look up a specific address (default: this machine's egress)
    -w, --watch [SECS]    repeat every SECS seconds (default 60), printing changes only
        --no-sources      skip third-party sources; only run local probes
    -h, --help            show this message

ENVIRONMENT:
    ABUSEIPDB_KEY         optional, raises risk-score accuracy
    SCAMALYTICS_KEY       optional
    IPQS_KEY              optional

The floating card (ipcheck.exe) uses the same engine as this CLI.",
        env!("CARGO_PKG_VERSION")
    );
}

/// Human-readable rendering, aligned with the card's layout so what you see on
/// screen and what you see in a terminal cannot drift.
fn render(snap: &ipcheck_lib::types::Snapshot) {
    let flag = if snap.country_code.is_empty() {
        "  ".to_string()
    } else {
        flag_emoji(&snap.country_code)
    };

    println!();
    println!("  {flag} {:<16} {}", snap.ip, snap.ip_type);
    println!();

    let s = &snap.scores;
    println!(
        "  纯净 {:>3}   风险 {:>3}   可信 {:>3}   一致 {:>3}     综合 {:>3}",
        s.purity, s.risk, s.confidence, s.consistency, snap.composite
    );
    println!();

    let line = |k: &str, v: &str| {
        if !v.is_empty() {
            println!("  {k:<8} {v}");
        }
    };
    line("国家", &format!("{} / {} / {}", snap.country, snap.region, snap.city));
    line("ASN", &format!("{} {}", snap.asn, snap.org));
    line("ISP", &snap.isp);
    line("时区", &snap.timezone);

    if snap.blacklist_checked > 0 {
        let mut v = if snap.blacklist_hits.is_empty() {
            format!("0/{} 命中", snap.blacklist_checked)
        } else {
            format!(
                "{} 命中: {}",
                snap.blacklist_hits.len(),
                snap.blacklist_hits.join(", ")
            )
        };
        // Policy listings are reported separately, and labelled, so a
        // consumer-range match is not mistaken for an abuse finding.
        if !snap.blacklist_policy.is_empty() {
            v.push_str(&format!(
                " (另 {} 条策略命中: {})",
                snap.blacklist_policy.len(),
                snap.blacklist_policy.join(", ")
            ));
        }
        line("黑名单", &v);
    }

    println!();
    println!("  ── 检测 ──");
    for c in &snap.checks {
        let mark = match c.agrees {
            Some(true) => "✓",
            Some(false) => "✗",
            None => "?",
        };
        println!("  {mark} {:<10} {}", c.label, c.detail);
    }

    if !snap.conflicts.is_empty() {
        println!();
        println!("  ── 源冲突 ──");
        for c in &snap.conflicts {
            println!("  ! {} — {} ↔ {}", c.field, c.a, c.b);
        }
    }

    println!();
    println!("  ── 数据源 ──");
    for s in &snap.sources {
        // Distinguish "ran and failed" from "we chose not to run it", so a
        // missing API key does not read as an outage.
        let (mark, timing) = match (s.ok, s.configured) {
            (true, _) => ("✓", format!("{:>5}ms", s.took_ms)),
            (false, true) => ("✗", format!("{:>5}ms", s.took_ms)),
            (false, false) => ("-", "     ".to_string()),
        };
        println!("  {mark} {:<12} {timing}  {}", s.name, s.note);
    }

    println!();
    println!("  耗时 {}ms", snap.took_ms);
    println!();
}

/// Regional indicator symbols for a two-letter country code. Falls back to the
/// raw code for anything that is not A-Z.
fn flag_emoji(cc: &str) -> String {
    let cc = cc.to_ascii_uppercase();
    let bytes = cc.as_bytes();
    if bytes.len() != 2 || !bytes.iter().all(|b| b.is_ascii_uppercase()) {
        return cc;
    }
    const BASE: u32 = 0x1F1E6;
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| char::from_u32(BASE + (b - b'A') as u32).unwrap_or('?'))
        .collect();
    chars.into_iter().collect()
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    if args.help {
        print_help();
        return;
    }

    // Keys from the environment so the CLI needs no config file.
    let cfg = Config {
        abuseipdb_key: std::env::var("ABUSEIPDB_KEY").unwrap_or_default(),
        scamalytics_key: std::env::var("SCAMALYTICS_KEY").unwrap_or_default(),
        ipqs_key: std::env::var("IPQS_KEY").unwrap_or_default(),
        enable_sources: !args.no_sources,
        ..Config::default()
    };

    let client = match ipcheck_lib::http::client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to build HTTP client: {e}");
            std::process::exit(1);
        }
    };

    match (args.watch, args.ip.clone()) {
        // One-shot lookup of a specific address.
        (None, Some(ip)) => {
            let snap = aggregator::refresh_for(&client, &cfg, &ip).await;
            if args.json {
                match serde_json::to_string_pretty(&snap) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("failed to serialise: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                render(&snap);
            }
        }
        // Watch mode: print only when something meaningful moved.
        (Some(secs), _) => {
            let mut last_ip = String::new();
            let mut last_risk: Option<u8> = None;
            loop {
                let snap = aggregator::refresh(&client, &cfg).await;
                let changed = snap.ip != last_ip || Some(snap.scores.risk) != last_risk;
                if changed {
                    if args.json {
                        if let Ok(s) = serde_json::to_string(&snap) {
                            println!("{s}");
                        }
                    } else {
                        let stamp = chrono::Local::now().format("%H:%M:%S");
                        println!(
                            "[{stamp}] {} {} 风险{} 综合{}",
                            snap.ip, snap.country_code, snap.scores.risk, snap.composite
                        );
                    }
                    last_ip = snap.ip.clone();
                    last_risk = Some(snap.scores.risk);
                }
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            }
        }
        // Default: probe this machine once.
        (None, None) => {
            let snap = aggregator::refresh(&client, &cfg).await;
            if args.json {
                match serde_json::to_string_pretty(&snap) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("failed to serialise: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                render(&snap);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_for_us_is_correct() {
        assert_eq!(flag_emoji("US"), "🇺🇸");
    }

    #[test]
    fn flag_for_cn_is_correct() {
        assert_eq!(flag_emoji("CN"), "🇨🇳");
    }

    #[test]
    fn lowercase_is_accepted() {
        assert_eq!(flag_emoji("gb"), "🇬🇧");
    }

    #[test]
    fn non_country_code_falls_back() {
        assert_eq!(flag_emoji(""), "");
        assert_eq!(flag_emoji("XYZ"), "XYZ");
        assert_eq!(flag_emoji("1!"), "1!");
    }
}
