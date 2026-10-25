// SPDX-License-Identifier: MPL-2.0

//! Signed ring policy, all in `git-agecrypt.toml`: `[config]` maps rings to
//! key names or recipients, `[keys]` names keys, `[policy]` holds the repo id
//! and a counter, and `[signature]`, last, seals everything above it plus
//! `.gitattributes` with the owner's git SSH signing key. Neither an unsigned
//! edit nor an older or foreign signed policy can redirect encryption in an
//! unlocked worktree.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{config::AppConfig, gitcli};

const TOML_FILE: &str = "git-agecrypt.toml";
const SIG_HEADER: &str = "[signature]";
/// ssh-keygen -Y namespace: a policy signature is never valid for a commit or tag.
const NAMESPACE: &str = "git-agecrypt-policy";
const FILTER_ATTR: &str = "filter=git-agecrypt";

/// `[policy]`: a repo id signed with the policy (so one repo's signed policy
/// is never accepted for another) and a counter.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Version {
    id: String,
    version: u64,
}

/// One read of the policy: verify, accept and pin use the same bytes.
pub(crate) struct Policy {
    message: Vec<u8>,
    gitattributes: String,
    /// The toml without its `[signature]`: the part the signature covers.
    signed: String,
    signature: Option<String>,
    version: Option<Version>,
}

impl Policy {
    pub(crate) fn read(root: &Path) -> Result<Self> {
        let read = |name: &str| {
            fs::read_to_string(root.join(name))
                .with_context(|| format!("policy file missing: {name}"))
        };
        let gitattributes = read(".gitattributes")?;
        let toml = read(TOML_FILE)?;
        let (signed, signature) = split_signature(&toml)?;
        Ok(Self {
            message: message(&gitattributes, signed),
            version: policy_version(signed)?,
            signed: signed.to_owned(),
            gitattributes,
            signature,
        })
    }

    fn versioned(&self) -> Result<&Version> {
        self.version.as_ref().with_context(|| {
            format!(
                "unsigned policy: {TOML_FILE} has no [policy]; the owner runs git-agecrypt sign"
            )
        })
    }

    pub(crate) fn version(&self) -> Result<u64> {
        Ok(self.versioned()?.version)
    }

    fn ring_lines(&self) -> Vec<String> {
        lines_with_filter(&self.gitattributes)
    }

    fn ring_dirs(&self) -> Result<Vec<String>> {
        validate_rings(&self.ring_lines(), &self.signed)
    }
}

fn message(gitattributes: &str, signed_toml: &str) -> Vec<u8> {
    let mut message = b"git-agecrypt-policy-v2\n".to_vec();
    for (name, data) in [(".gitattributes", gitattributes), (TOML_FILE, signed_toml)] {
        message.extend_from_slice(format!("{name}\n{}\n", data.len()).as_bytes());
        message.extend_from_slice(data.as_bytes());
    }
    message
}

fn signature_block(sig: &str) -> String {
    format!("{SIG_HEADER}\nssh = \"\"\"\n{sig}\"\"\"\n")
}

/// Split the toml at `[signature]`, which must close the file: everything
/// above it is signed, and anything after it would not be.
fn split_signature(toml: &str) -> Result<(&str, Option<String>)> {
    let at = toml.match_indices(SIG_HEADER).map(|(i, _)| i).find(|&i| {
        (i == 0 || toml.as_bytes()[i - 1] == b'\n')
            && toml[i + SIG_HEADER.len()..].starts_with('\n')
    });
    let Some(at) = at else {
        if toml::from_str::<toml::Table>(toml).is_ok_and(|t| t.contains_key("signature")) {
            bail!("{TOML_FILE}: [signature] must be its own table, at the end");
        }
        return Ok((toml, None));
    };
    let (signed, tail) = toml.split_at(at);
    let sig = toml::from_str::<toml::Table>(tail)
        .ok()
        .and_then(|t| Some(t.get("signature")?.get("ssh")?.as_str()?.to_owned()))
        .with_context(|| {
            format!("{TOML_FILE}: [signature] must hold ssh = the policy signature")
        })?;
    if tail != signature_block(&sig) {
        bail!(
            "{TOML_FILE}: only the signature may follow [signature]; anything there would be unsigned"
        );
    }
    Ok((signed, Some(sig)))
}

/// `[policy]` of the signed toml, when it has one.
fn policy_version(signed: &str) -> Result<Option<Version>> {
    let table: toml::Table =
        toml::from_str(signed).with_context(|| format!("{TOML_FILE} is not valid TOML"))?;
    table
        .get("policy")
        .map(|p| {
            p.clone()
                .try_into()
                .context("[policy] must hold an id and a version")
        })
        .transpose()
}

fn lines_with_filter(gitattributes: &str) -> Vec<String> {
    gitattributes
        .lines()
        .filter(|l| l.split_whitespace().any(|w| w == FILTER_ATTR))
        .map(str::to_owned)
        .collect()
}

/// A ring is a whole `<dir>/**`, so every file type inside it is encrypted,
/// and the toml keys must be exactly the ring patterns. Returns `<dir>/`.
fn validate_rings(lines: &[String], toml: &str) -> Result<Vec<String>> {
    let mut patterns: Vec<String> = lines
        .iter()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect();
    let bad: Vec<&String> = patterns
        .iter()
        .filter(|p| {
            let dir = p.strip_suffix("/**").unwrap_or("");
            dir.is_empty() || dir.contains(['*', '?', '[', ']', '!', '\\'])
        })
        .collect();
    if !bad.is_empty() {
        bail!("rings must be whole directories (<dir>/**), not: {bad:?}");
    }
    let table: toml::Table = toml::from_str(toml)?;
    let mut keys: Vec<String> = table
        .get("config")
        .and_then(|c| c.as_table())
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    patterns.sort();
    if keys != patterns {
        bail!("{TOML_FILE} keys must be exactly the ring patterns of .gitattributes");
    }
    Ok(patterns
        .iter()
        .map(|p| p.trim_end_matches('*').to_owned())
        .collect())
}

/// Recipients per ring with key names resolved. A ring mixing classic and
/// post-quantum recipients is refused here rather than at the first `git add`.
fn recipients_per_ring(signed: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let rings = AppConfig::parse(signed)?.resolved()?;
    for (ring, recipients) in &rings {
        let pq = recipients
            .iter()
            .filter(|r| r.starts_with("age1pq1"))
            .count();
        if pq != 0 && pq != recipients.len() {
            bail!("{ring} mixes age1pq1 and classic recipients: age encrypts to one kind only");
        }
        crate::age::validate_public_keys(recipients)?;
    }
    Ok(rings)
}

/// `~/.config/git-agecrypt`, with home taken from the account database rather
/// than `$HOME`: repo-controlled env (mise, direnv) cannot move the anchor.
#[cfg(unix)]
pub(crate) fn trust_dir() -> Result<PathBuf> {
    use std::{ffi::CStr, os::unix::ffi::OsStrExt};
    // SAFETY: getpwuid returns a pointer into static storage or null; the
    // string is copied out before any other passwd call.
    let home = unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            bail!("no home directory for this account");
        }
        PathBuf::from(std::ffi::OsStr::from_bytes(
            CStr::from_ptr((*pw).pw_dir).to_bytes(),
        ))
    };
    if !home.is_absolute() {
        bail!("the account's home directory is not absolute: pass --trust");
    }
    Ok(home.join(".config").join("git-agecrypt"))
}

#[cfg(not(unix))]
pub(crate) fn trust_dir() -> Result<PathBuf> {
    bail!("pass --trust: no account database lookup on this platform")
}

fn required(root: &Path, key: &str) -> Result<String> {
    gitcli::config_get(root, key)?.with_context(|| format!("git config {key} is not set"))
}

fn unique() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    blake3::hash(format!("{nanos}.{}", std::process::id()).as_bytes()).to_hex()[..32].to_owned()
}

/// A fresh private directory: create_dir fails rather than reusing a planted one.
fn private_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("git-agecrypt-sign.{}", unique()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&dir)?;
    Ok(dir)
}

/// Run `f` in a fresh private directory, removed afterwards.
fn in_private_dir<T>(f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let tmp = private_dir()?;
    let result = f(&tmp);
    let _ = fs::remove_dir_all(&tmp);
    result
}

fn signing_key_file(value: &str, tmp: &Path) -> Result<PathBuf> {
    // Same forms git accepts for user.signingkey with gpg.format=ssh.
    let literal = value.strip_prefix("key::").unwrap_or(value);
    if ["ssh-", "ecdsa-", "sk-"]
        .iter()
        .any(|p| literal.starts_with(p))
    {
        let path = tmp.join("signing.pub");
        fs::write(&path, format!("{literal}\n"))?;
        return Ok(path);
    }
    // git expands a leading `~/` from $HOME; ssh-keygen would not.
    if let Some(rest) = value.strip_prefix("~/") {
        let home = std::env::var_os("HOME").context("user.signingkey uses ~/ but HOME is unset")?;
        return Ok(PathBuf::from(home).join(rest));
    }
    if value.starts_with('~') {
        bail!("user.signingkey: ~user paths are not supported, use an absolute path");
    }
    Ok(PathBuf::from(value))
}

/// Bump `[policy]` (keeping the repo id, minting one the first time) and sign
/// into `[signature]`. Each signature supersedes every older one.
pub(crate) fn sign(root: &Path) -> Result<u64> {
    if required(root, "gpg.format")? != "ssh" {
        bail!("gpg.format must be ssh: the policy is signed like your commits");
    }
    // git's own default when gpg.ssh.program is unset.
    let program =
        gitcli::config_get(root, "gpg.ssh.program")?.unwrap_or_else(|| "ssh-keygen".into());
    let key_value = required(root, "user.signingkey")?;
    let toml_path = root.join(TOML_FILE);
    let toml = fs::read_to_string(&toml_path)
        .with_context(|| format!("policy file missing: {TOML_FILE}"))?;
    let gitattributes = fs::read_to_string(root.join(".gitattributes"))?;
    let (signed, _) = split_signature(&toml)?;
    validate_rings(&lines_with_filter(&gitattributes), signed)?;
    let rings = recipients_per_ring(signed)?;
    let next = match policy_version(signed)? {
        Some(current) => Version {
            version: current.version + 1,
            ..current
        },
        None => Version {
            id: unique(),
            version: 1,
        },
    };
    let mut doc: toml_edit::DocumentMut = signed.parse()?;
    if !doc.contains_table("policy") {
        doc.insert("policy", toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let table = doc["policy"]
        .as_table_mut()
        .context("[policy] must be a table")?;
    table["id"] = toml_edit::value(next.id.as_str());
    table["version"] = toml_edit::value(i64::try_from(next.version)?);
    let signed = format!("{}\n\n", doc.to_string().trim_end());
    let sig = in_private_dir(|tmp| {
        let key = signing_key_file(&key_value, tmp)?;
        let msg = tmp.join("policy");
        fs::write(&msg, message(&gitattributes, &signed))?;
        let status = Command::new(&program)
            .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
            .arg(&key)
            .arg(&msg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("cannot run {program}"))?;
        if !status.success() {
            bail!("{program} -Y sign failed ({status})");
        }
        Ok(fs::read_to_string(tmp.join("policy.sig"))?)
    })?;
    let tmp = root.join(format!("{TOML_FILE}.tmp{}", std::process::id()));
    fs::write(&tmp, format!("{signed}{}", signature_block(&sig)))?;
    fs::rename(&tmp, &toml_path)?;
    let before = gitcli::run(root, &["show", &format!("HEAD:{TOML_FILE}")])
        .ok()
        .and_then(|head| recipients_per_ring(split_signature(&head).ok()?.0).ok());
    for (ring, now) in &rings {
        if before
            .as_ref()
            .and_then(|b| b.get(ring))
            .is_some_and(|was| was != now)
        {
            eprintln!(
                "recipients of {ring} changed: after `git-agecrypt on`, run \
                 `git-agecrypt rekey {}` so unchanged files drop the old keys",
                ring.trim_end_matches("/**")
            );
        }
    }
    Ok(next.version)
}

/// Check the signature against the anchor; return the signer principal.
pub(crate) fn verify(trust: &Path, policy: &Policy) -> Result<String> {
    let allowed = trust.join("allowed_signers");
    if !allowed.is_file() {
        bail!(
            "no trust anchor: create {} (OpenSSH allowed_signers)",
            allowed.display()
        );
    }
    let Some(signature) = &policy.signature else {
        bail!("unsigned policy: {TOML_FILE} has no [signature]; the owner runs git-agecrypt sign");
    };
    policy.versioned()?;
    policy.ring_dirs()?;
    in_private_dir(|tmp| {
        let sig = tmp.join("policy.sig");
        fs::write(&sig, signature)?;
        let found = Command::new("ssh-keygen")
            .args(["-Y", "find-principals", "-s"])
            .arg(&sig)
            .arg("-f")
            .arg(&allowed)
            .output()
            .context("cannot run ssh-keygen")?;
        let principals = String::from_utf8(found.stdout)?;
        let Some(principal) = principals
            .split_whitespace()
            .next()
            .filter(|_| found.status.success())
        else {
            bail!("the policy is not signed by a key in {}", allowed.display());
        };
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&allowed)
            .args(["-I", principal, "-n", NAMESPACE, "-s"])
            .arg(&sig)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .context("no stdin")?
            .write_all(&policy.message)?;
        if !child.wait()?.success() {
            bail!("the signature does not match the current rings or recipients");
        }
        Ok(principal.to_owned())
    })
}
