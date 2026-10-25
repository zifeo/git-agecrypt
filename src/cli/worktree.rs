// SPDX-License-Identifier: MPL-2.0

//! `on` / `off`: unlock one worktree only. `git-agecrypt init` writes the
//! shared `.git/config`, which unlocks every worktree of the clone (agents
//! included) at once. Here the shared config holds a baseline that fails
//! closed (the process filter, locked unless pinned, and the commit hook); the
//! unlock is a pin in `<gitdir>/git-agecrypt.gitconfig`, pulled in by an exact
//! `includeIf.gitdir`. `git worktree add` does not copy it, a moved repo no
//! longer matches it: both fall back to locked.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};

use super::public::shell_quote;
use crate::{
    ctx::{Context, IDENTITY_ENV},
    git::Repository,
    gitcli, policy,
};

const INCLUDE: &str = "git-agecrypt.gitconfig";
const HOOK: &str = "git-agecrypt-check";
/// Every way a commit gets written by `git commit` or `git merge`.
const HOOK_EVENTS: [&str; 2] = ["pre-commit", "pre-merge-commit"];
/// First line of the shared info/attributes this tool owns and rewrites.
const INFO_MARKER: &str = "# managed by git-agecrypt on: rings from the signed policy\n";

fn gitdir(root: &Path) -> Result<PathBuf> {
    Ok(fs::canonicalize(
        gitcli::run(root, &["rev-parse", "--absolute-git-dir"])?.trim(),
    )?)
}

/// `includeIf.gitdir:` takes a wildmatch pattern: escape it to an exact path.
/// No trailing slash, so the main worktree does not match `.git/worktrees/*`.
fn include_section(gitdir: &Path) -> String {
    let mut pattern = String::new();
    for c in gitdir.to_string_lossy().chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    format!("includeIf.gitdir:{pattern}")
}

/// git runs this binary on every checkout and commit of the clone: no commit
/// may be able to edit it. The canonical path is both checked and written.
fn canonical_exe(root: &Path, exe: &str) -> Result<String> {
    let exe = fs::canonicalize(exe)?;
    if exe.starts_with(fs::canonicalize(root)?) {
        bail!(
            "git-agecrypt runs from inside this repo ({}): install it outside",
            exe.display()
        );
    }
    Ok(exe
        .to_str()
        .context("git-agecrypt path is not UTF-8")?
        .to_owned())
}

fn local(root: &Path, args: &[&str]) {
    let mut full = vec!["config", "--local"];
    full.extend(args);
    let _ = gitcli::output(root, &full);
}

/// Shared config for every worktree: decrypting needs a pin; staging plaintext
/// into a ring and committing without the gate do not get past it.
fn write_baseline(root: &Path, exe: &str) -> Result<()> {
    // An `init` unlock decrypts (and its textconv shows diffs) in every worktree.
    local(root, &["--unset-all", "filter.git-agecrypt.smudge"]);
    local(root, &["--unset-all", "filter.git-agecrypt.clean"]);
    local(root, &["--remove-section", "diff.git-agecrypt"]);
    let quoted = shell_quote(exe);
    for (key, value) in [
        ("filter.git-agecrypt.required", "true".to_owned()),
        ("filter.git-agecrypt.process", format!("{quoted} process")),
        (
            &format!("hook.{HOOK}.command"),
            format!("{quoted} check --staged"),
        ),
    ] {
        gitcli::run(root, &["config", "--local", key, &value])?;
    }
    // A merge commit skips pre-commit: without pre-merge-commit, a merged
    // branch could bring plaintext into a ring unchecked.
    let event = format!("hook.{HOOK}.event");
    local(root, &["--unset-all", &event]);
    for hook in HOOK_EVENTS {
        gitcli::run(root, &["config", "--local", "--add", &event, hook])?;
        let hooks = gitcli::run(root, &["hook", "list", hook]).unwrap_or_default();
        if !hooks.split_whitespace().any(|h| h == HOOK) {
            bail!("this git does not run config hooks (hook.<name>.command): upgrade git");
        }
    }
    Ok(())
}

fn write_unlock(root: &Path, gitdir: &Path, exe: &str, pinned: &str) -> Result<()> {
    let include = gitdir.join(INCLUDE);
    let _ = fs::remove_file(&include);
    let inc = include.to_str().context("gitdir is not UTF-8")?;
    gitcli::run(
        root,
        &["config", "-f", inc, "git-agecrypt.policy.pinned", pinned],
    )?;
    let textconv = format!("{} textconv", shell_quote(exe));
    gitcli::run(
        root,
        &["config", "-f", inc, "diff.git-agecrypt.textconv", &textconv],
    )?;
    let section = include_section(gitdir);
    local(root, &["--remove-section", &section]);
    gitcli::run(
        root,
        &["config", "--local", &format!("{section}.path"), inc],
    )?;
    Ok(())
}

fn clear_unlock(root: &Path, gitdir: &Path) {
    local(root, &["--remove-section", &include_section(gitdir)]);
    let _ = fs::remove_file(gitdir.join(INCLUDE));
}

fn info_attributes(root: &Path) -> Result<PathBuf> {
    let path =
        PathBuf::from(gitcli::run(root, &["rev-parse", "--git-path", "info/attributes"])?.trim());
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

fn write_info_attributes(root: &Path, lines: &[String]) -> Result<()> {
    // info/attributes outranks every in-tree .gitattributes, nested ones included.
    let path = info_attributes(root)?;
    if let Ok(existing) = fs::read_to_string(&path)
        && !existing.starts_with(INFO_MARKER)
    {
        bail!(
            "{} exists and is not managed by git-agecrypt; merge it by hand",
            path.display()
        );
    }
    fs::create_dir_all(path.parent().context("info/attributes has no parent")?)?;
    let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
    Ok(fs::write(path, format!("{INFO_MARKER}{body}"))?)
}

fn filtered_now(root: &Path) -> Result<HashSet<String>> {
    gitcli::filtered(root, &gitcli::tracked(root, &[])?)
}

fn refuse_dirty(root: &Path, paths: &HashSet<String>, verb: &str) -> Result<()> {
    let dirty: Vec<String> = gitcli::dirty(root)?
        .into_iter()
        .filter(|p| paths.contains(p))
        .collect();
    if !dirty.is_empty() {
        bail!(
            "uncommitted changes under encrypted paths; commit or stash, then {verb}:\n{}",
            dirty.join("\n")
        );
    }
    Ok(())
}

/// A ring file git never saw is not refreshed: it would stay plaintext.
fn refuse_untracked(root: &Path, verb: &str) -> Result<()> {
    let mut stray: Vec<String> = gitcli::filtered(root, &gitcli::untracked(root)?)?
        .into_iter()
        .collect();
    if !stray.is_empty() {
        stray.sort();
        bail!(
            "untracked files under encrypted paths stay plaintext; commit or remove them, then {verb}:\n{}",
            stray.join("\n")
        );
    }
    Ok(())
}

/// Re-check-out `paths` through the current filter. `git checkout` skips
/// stat-clean files, so make their stat stale instead of deleting them: a
/// checkout that fails halfway leaves the old content, not holes.
fn refresh(root: &Path, paths: &HashSet<String>) -> Result<()> {
    let stale = UNIX_EPOCH + Duration::from_secs(1);
    for path in paths {
        // The owner may set the times of a read-only file it cannot open for
        // writing; skipping it would leave its plaintext behind.
        #[cfg(unix)]
        let file = fs::File::open(root.join(path));
        #[cfg(not(unix))]
        let file = fs::File::options().write(true).open(root.join(path));
        match file {
            Ok(f) => f
                .set_modified(stale)
                .with_context(|| format!("cannot make {path} stale"))?,
            // A deleted file is checked out again anyway.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::Error::from(e).context(format!("cannot open {path}"))),
        }
    }
    let paths: Vec<String> = paths.iter().cloned().collect();
    gitcli::run_with_paths(root, &["checkout"], &paths)
}

/// After `off`, every encrypted file on disk must be the blob the index
/// holds: a file git judged up to date would still be plaintext.
fn ensure_index_content(root: &Path, paths: &HashSet<String>) -> Result<()> {
    let index = gitcli::index(root)?;
    let oids: Vec<String> = paths
        .iter()
        .filter_map(|p| index.get(p).map(|e| e.oid.clone()))
        .collect();
    let blobs = gitcli::blobs(root, &oids)?;
    let mut left: Vec<&str> = paths
        .iter()
        .filter(|p| {
            let file = root.join(p);
            let regular = fs::symlink_metadata(&file).is_ok_and(|m| m.is_file());
            regular
                && index
                    .get(*p)
                    .is_some_and(|e| fs::read(&file).ok().as_ref() != blobs.get(&e.oid))
        })
        .map(String::as_str)
        .collect();
    if !left.is_empty() {
        left.sort();
        bail!(
            "still not ciphertext after off, check these by hand:\n{}",
            left.join("\n")
        );
    }
    Ok(())
}

/// Ring files whose disk content is exactly their index blob: ciphertext a
/// keyless smudge left. Only those: a checkout over anything else could lose
/// work.
fn index_ciphertext(root: &Path, paths: &HashSet<String>) -> Result<HashSet<String>> {
    let index = gitcli::index(root)?;
    let oids: Vec<String> = paths
        .iter()
        .filter_map(|p| index.get(p).map(|e| e.oid.clone()))
        .collect();
    let blobs = gitcli::blobs(root, &oids)?;
    Ok(paths
        .iter()
        .filter(|p| {
            let on_disk = fs::read(root.join(p)).ok();
            index
                .get(*p)
                .and_then(|e| blobs.get(&e.oid))
                .is_some_and(|blob| {
                    blob.starts_with(crate::age::MAGIC) && on_disk.as_ref() == Some(blob)
                })
        })
        .cloned()
        .collect())
}

pub(crate) fn on<C: Context>(ctx: &C, trust: Option<PathBuf>) -> Result<()> {
    let root = ctx.repo().workdir().to_path_buf();
    let exe = canonical_exe(&root, &ctx.current_exe()?)?;
    if !ctx.has_identity_source()? {
        bail!(
            "no key: {IDENTITY_ENV} is empty and no identityCommand or identity is set; \
             run on where your secret manager fills {IDENTITY_ENV}"
        );
    }
    let trust = match trust {
        Some(t) => t,
        None => policy::trust_dir()?,
    };
    let policy = policy::Policy::read(&root)?;
    let signer = policy::verify(&trust, &policy)?;
    policy::accept(&root, &policy)?;

    let gitdir = gitdir(&root)?;
    // Our include file still in the gitdir but not matching (the repo moved)
    // also means plaintext on disk: re-pin rather than refuse.
    let repinning = ctx.pinned_policy()?.is_some() || gitdir.join(INCLUDE).exists();
    let before = filtered_now(&root)?;
    write_info_attributes(&root, &policy.ring_lines())?;
    let after = filtered_now(&root)?;
    let refresh_set = if repinning {
        // Already plaintext: only files that leave the rings must turn back
        // into ciphertext. Refuse if one of them holds unsaved work.
        let leaving: HashSet<String> = before.difference(&after).cloned().collect();
        for path in &leaving {
            if !ctx.matches_cache(&root.join(path))? {
                bail!("{path} leaves the rings with uncommitted changes: commit or move it first");
            }
        }
        // A git command without the key left these as ciphertext.
        leaving
            .union(&index_ciphertext(&root, &after)?)
            .cloned()
            .collect()
    } else {
        refuse_dirty(&root, &after, "on")?;
        after
    };
    write_baseline(&root, &exe)?;
    write_unlock(&root, &gitdir, &exe, &policy.digest())?;
    if let Err(e) = refresh(&root, &refresh_set) {
        // Back to locked, with ciphertext everywhere, before reporting.
        clear_unlock(&root, &gitdir);
        refresh(&root, &refresh_set)
            .context("git-agecrypt on failed and could not restore ciphertext")?;
        return Err(e.context("git-agecrypt on failed; this worktree stays locked"));
    }
    println!(
        "git-agecrypt on in this worktree: policy v{} signed by {signer}.",
        policy.version()?
    );
    println!("other worktrees stay locked. lock this one with: git-agecrypt off");
    Ok(())
}

pub(crate) fn off<C: Context>(ctx: &C) -> Result<()> {
    let root = ctx.repo().workdir().to_path_buf();
    let paths = filtered_now(&root)?;
    refuse_dirty(&root, &paths, "off")?;
    refuse_untracked(&root, "off")?;
    clear_unlock(&root, &gitdir(&root)?);
    refresh(&root, &paths)?;
    ensure_index_content(&root, &paths)?;
    // The cache holds a plaintext hash per file.
    ctx.remove_sidecar_files()?;
    println!("git-agecrypt off in this worktree: encrypted files are ciphertext again.");
    Ok(())
}
