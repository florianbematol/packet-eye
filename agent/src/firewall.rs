//! Windows Firewall integration.
//!
//! Packet Eye manages its own block rules, all tagged with the firewall
//! group `"Packet Eye"` so they're easy to list, toggle and remove
//! without touching anything else on the system.
//!
//! Rules are driven through the built-in `NetSecurity` PowerShell module
//! (`New-NetFirewallRule`, `Get-NetFirewallRule`…), whose output is not
//! localised — unlike `netsh`. User-supplied values are passed through
//! environment variables, never interpolated into the script, so there's
//! no command-injection surface. Mutations require Administrator rights.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const GROUP: &str = "Packet Eye";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub enabled: bool,
    /// `Inbound` or `Outbound`.
    pub direction: String,
    pub action: String,
    /// Remote addresses (`["Any"]` for program rules).
    #[serde(default)]
    pub remote: Vec<String>,
    /// Program path (`"Any"` for address rules).
    #[serde(default)]
    pub program: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    In,
    Out,
    Both,
}

impl RuleDirection {
    fn ps(self) -> &'static [&'static str] {
        match self {
            RuleDirection::In => &["Inbound"],
            RuleDirection::Out => &["Outbound"],
            RuleDirection::Both => &["Outbound", "Inbound"],
        }
    }
}

/// What to block.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BlockTarget {
    /// One or more IPs / CIDRs, comma-separated.
    Ip { value: String },
    /// An executable, by absolute path.
    Program { path: String },
    /// A running process; its executable path is resolved server-side.
    Process {
        #[serde(default)]
        pid: Option<u32>,
        #[serde(default)]
        name: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("{0}")]
    Invalid(String),
    #[error("Administrator rights are required to change firewall rules")]
    NotAdmin,
    #[error("rule not found or not managed by Packet Eye")]
    NotFound,
    #[error("firewall management is only available on Windows")]
    Unsupported,
    #[error("PowerShell failed: {0}")]
    Script(String),
}

// --------------------------------------------------------------------
// Validation
// --------------------------------------------------------------------

/// Validate and normalise a comma-separated list of IPs / CIDRs.
pub fn normalize_addresses(input: &str) -> Result<Vec<String>, FirewallError> {
    let mut out = Vec::new();
    for raw in input.split(|c: char| c == ',' || c.is_whitespace()) {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let (ip_str, prefix) = match item.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (item, None),
        };
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| FirewallError::Invalid(format!("not an IP address: {item}")))?;
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(FirewallError::Invalid(format!(
                "refusing to block {item}: it would cut the agent off"
            )));
        }
        let max = if ip.is_ipv4() { 32 } else { 128 };
        match prefix {
            Some(p) => {
                let n: u8 = p
                    .parse()
                    .ok()
                    .filter(|n| *n <= max)
                    .ok_or_else(|| FirewallError::Invalid(format!("bad prefix length: {item}")))?;
                if n < 8 {
                    return Err(FirewallError::Invalid(format!(
                        "prefix /{n} is too broad: {item}"
                    )));
                }
                out.push(format!("{ip}/{n}"));
            }
            None => out.push(ip.to_string()),
        }
        if out.len() > 64 {
            return Err(FirewallError::Invalid("too many addresses (max 64)".into()));
        }
    }
    if out.is_empty() {
        return Err(FirewallError::Invalid("no address given".into()));
    }
    Ok(out)
}

pub fn validate_program(path: &str) -> Result<String, FirewallError> {
    let p = Path::new(path.trim());
    if !p.is_absolute() {
        return Err(FirewallError::Invalid("program path must be absolute".into()));
    }
    let is_exe = p
        .extension()
        .map(|e| e.eq_ignore_ascii_case("exe"))
        .unwrap_or(false);
    if !is_exe {
        return Err(FirewallError::Invalid("program must be an .exe file".into()));
    }
    if !p.is_file() {
        return Err(FirewallError::Invalid(format!("file not found: {}", p.display())));
    }
    Ok(p.display().to_string())
}

/// Strip control characters and cap length for user-supplied notes.
fn clean_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

/// Executable path of a running process, by PID or by image name.
pub fn resolve_process_path(pid: Option<u32>, name: Option<&str>) -> Result<String, FirewallError> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new();
    let kind = ProcessRefreshKind::new().with_exe(UpdateKind::Always);
    if let Some(pid) = pid {
        let spid = Pid::from_u32(pid);
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[spid]), true, kind);
        if let Some(exe) = sys.process(spid).and_then(|p| p.exe()) {
            return Ok(exe.display().to_string());
        }
    }
    if let Some(name) = name {
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        let found = sys
            .processes()
            .values()
            .find(|p| p.name().to_string_lossy().eq_ignore_ascii_case(name))
            .and_then(|p| p.exe());
        if let Some(exe) = found {
            return Ok(exe.display().to_string());
        }
    }
    Err(FirewallError::Invalid(
        "process isn't running anymore — block it by executable path instead".into(),
    ))
}

// --------------------------------------------------------------------
// PowerShell plumbing
// --------------------------------------------------------------------

const PRELUDE: &str = "$ErrorActionPreference = 'Stop'\n\
[Console]::OutputEncoding = [Text.Encoding]::UTF8\n";

const ADMIN_CHECK: &str = "$id = [Security.Principal.WindowsIdentity]::GetCurrent()\n\
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { [Console]::Error.WriteLine('PE_NOT_ADMIN'); exit 3 }\n";

#[cfg(windows)]
fn run_ps(script: &str, env: &[(&str, &str)]) -> Result<String, FirewallError> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // -EncodedCommand expects base64 of the UTF-16LE script. Values come
    // in through environment variables, never through the script text.
    let full = format!("{PRELUDE}{script}");
    let utf16: Vec<u8> = full.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let encoded = base64_encode(&utf16);
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| FirewallError::Script(format!("cannot start powershell: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if stderr.contains("PE_NOT_ADMIN") {
        return Err(FirewallError::NotAdmin);
    }
    if stderr.contains("PE_NOT_FOUND") {
        return Err(FirewallError::NotFound);
    }
    if !out.status.success() {
        let msg = stderr
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("unknown error")
            .to_string();
        return Err(FirewallError::Script(msg));
    }
    Ok(stdout)
}

#[cfg(not(windows))]
fn run_ps(_script: &str, _env: &[(&str, &str)]) -> Result<String, FirewallError> {
    Err(FirewallError::Unsupported)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

// --------------------------------------------------------------------
// Operations (all blocking — call from spawn_blocking)
// --------------------------------------------------------------------

const LIST_SCRIPT: &str = "$rules = @(Get-NetFirewallRule -Group $env:PE_GROUP -ErrorAction SilentlyContinue)\n\
$out = @(foreach ($r in $rules) {\n\
  $a = $r | Get-NetFirewallAddressFilter\n\
  $p = $r | Get-NetFirewallApplicationFilter\n\
  [pscustomobject]@{\n\
    id = $r.Name; name = $r.DisplayName; description = $r.Description\n\
    enabled = (\"$($r.Enabled)\" -eq 'True')\n\
    direction = \"$($r.Direction)\"; action = \"$($r.Action)\"\n\
    remote = @($a.RemoteAddress | ForEach-Object { \"$_\" })\n\
    program = \"$($p.Program)\"\n\
  }\n\
})\n\
ConvertTo-Json -InputObject $out -Depth 4 -Compress\n";

fn add_script() -> String {
    format!(
        "{ADMIN_CHECK}\
$p = @{{ DisplayName = $env:PE_NAME; Group = $env:PE_GROUP; Description = $env:PE_DESC;\n\
        Direction = $env:PE_DIR; Action = 'Block'; Profile = 'Any'; Enabled = 'True' }}\n\
if ($env:PE_REMOTE) {{ $p.RemoteAddress = $env:PE_REMOTE -split ',' }}\n\
if ($env:PE_PROGRAM) {{ $p.Program = $env:PE_PROGRAM }}\n\
(New-NetFirewallRule @p).Name\n"
    )
}

pub fn list_rules() -> Result<Vec<FirewallRule>, FirewallError> {
    let json = run_ps(LIST_SCRIPT, &[("PE_GROUP", GROUP)])?;
    if json.is_empty() {
        return Ok(Vec::new());
    }
    let mut rules: Vec<FirewallRule> = serde_json::from_str(&json)
        .map_err(|e| FirewallError::Script(format!("unexpected output: {e}")))?;
    rules.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(rules)
}

/// Create one block rule per direction. Returns the new rule ids.
pub fn add_block(
    target: &BlockTarget,
    direction: RuleDirection,
    note: Option<&str>,
) -> Result<Vec<String>, FirewallError> {
    let (label, remote, program) = match target {
        BlockTarget::Ip { value } => {
            let addrs = normalize_addresses(value)?;
            let label = if addrs.len() == 1 {
                addrs[0].clone()
            } else {
                format!("{} (+{})", addrs[0], addrs.len() - 1)
            };
            (label, addrs.join(","), String::new())
        }
        BlockTarget::Program { path } => {
            let p = validate_program(path)?;
            let label = Path::new(&p)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| p.clone());
            (label, String::new(), p)
        }
        BlockTarget::Process { pid, name } => {
            let p = validate_program(&resolve_process_path(*pid, name.as_deref())?)?;
            let label = Path::new(&p)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| p.clone());
            (label, String::new(), p)
        }
    };

    let created = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let note = note.map(|n| clean_text(n, 200)).filter(|n| !n.is_empty());
    let desc = match &note {
        Some(n) => format!("Created by Packet Eye on {created}. {n}"),
        None => format!("Created by Packet Eye on {created}."),
    };

    let script = add_script();

    let mut ids = Vec::new();
    for dir in direction.ps() {
        let name = format!("Packet Eye - block {label} ({})", dir.to_lowercase());
        let id = run_ps(
            &script,
            &[
                ("PE_NAME", &name),
                ("PE_GROUP", GROUP),
                ("PE_DESC", &desc),
                ("PE_DIR", dir),
                ("PE_REMOTE", &remote),
                ("PE_PROGRAM", &program),
            ],
        )?;
        ids.push(id.lines().last().unwrap_or("").trim().to_string());
    }
    Ok(ids)
}

fn ensure_managed_script(action: &str) -> String {
    format!(
        "{ADMIN_CHECK}\
$r = Get-NetFirewallRule -Name $env:PE_ID -ErrorAction SilentlyContinue\n\
if (-not $r -or $r.Group -ne $env:PE_GROUP) {{ [Console]::Error.WriteLine('PE_NOT_FOUND'); exit 4 }}\n\
{action}\n"
    )
}

fn validate_id(id: &str) -> Result<(), FirewallError> {
    // Rule names generated by Windows are `{GUID}`; be strict anyway.
    let ok = !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_alphanumeric() || "{}-_".contains(c));
    if ok {
        Ok(())
    } else {
        Err(FirewallError::Invalid("bad rule id".into()))
    }
}

pub fn set_enabled(id: &str, enabled: bool) -> Result<(), FirewallError> {
    validate_id(id)?;
    let script = ensure_managed_script("Set-NetFirewallRule -Name $env:PE_ID -Enabled $env:PE_ENABLED");
    run_ps(
        &script,
        &[
            ("PE_ID", id),
            ("PE_GROUP", GROUP),
            ("PE_ENABLED", if enabled { "True" } else { "False" }),
        ],
    )?;
    Ok(())
}

pub fn delete_rule(id: &str) -> Result<(), FirewallError> {
    validate_id(id)?;
    let script = ensure_managed_script("Remove-NetFirewallRule -Name $env:PE_ID");
    run_ps(&script, &[("PE_ID", id), ("PE_GROUP", GROUP)])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation() {
        assert_eq!(
            normalize_addresses("1.2.3.4, 10.0.0.0/8 2001:db8::1").unwrap(),
            vec!["1.2.3.4", "10.0.0.0/8", "2001:db8::1"]
        );
        assert!(normalize_addresses("127.0.0.1").is_err());
        assert!(normalize_addresses("0.0.0.0/0").is_err());
        assert!(normalize_addresses("1.2.3.4/2").is_err());
        assert!(normalize_addresses("1.2.3.4/40").is_err());
        assert!(normalize_addresses("evil.com").is_err());
        assert!(normalize_addresses("1.2.3.4; Remove-Item").is_err());
        assert!(normalize_addresses("  ").is_err());
    }

    #[test]
    fn program_validation() {
        assert!(validate_program("notepad.exe").is_err());
        assert!(validate_program("C:\\Windows\\win.ini").is_err());
        #[cfg(windows)]
        assert!(validate_program("C:\\Windows\\System32\\notepad.exe").is_ok());
    }

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rule_id_validation() {
        assert!(validate_id("{8A2B5C1E-1111-2222-3333-444455556666}").is_ok());
        assert!(validate_id("x'; Remove-NetFirewallRule -All #").is_err());
        assert!(validate_id("").is_err());
    }

    /// Parse (without running) every generated script with PowerShell's
    /// own parser, so a syntax slip can't reach a real firewall call.
    #[cfg(windows)]
    #[test]
    fn powershell_scripts_parse() {
        let check = "$errs = $null\n\
[void][System.Management.Automation.Language.Parser]::ParseInput($env:PE_SRC, [ref]$null, [ref]$errs)\n\
if ($errs.Count) { throw (($errs | ForEach-Object { $_.Message }) -join '; ') }\n\
'ok'\n";
        let scripts = [
            LIST_SCRIPT.to_string(),
            add_script(),
            ensure_managed_script("Set-NetFirewallRule -Name $env:PE_ID -Enabled $env:PE_ENABLED"),
            ensure_managed_script("Remove-NetFirewallRule -Name $env:PE_ID"),
        ];
        for s in scripts {
            let src = format!("{PRELUDE}{s}");
            let out = run_ps(check, &[("PE_SRC", &src)]).expect("script must parse");
            assert_eq!(out, "ok");
        }
    }

    /// Listing is read-only and works without elevation.
    #[cfg(windows)]
    #[test]
    fn list_rules_runs() {
        list_rules().expect("listing Packet Eye rules");
    }
}
