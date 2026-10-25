// SPDX-License-Identifier: MPL-2.0

//! Thin helpers over the git CLI for the worktree commands (on, off, check,
//! sign, rekey). They need what libgit2 does not offer here: config hooks,
//! `includeIf`, check-attr in bulk, and checkout through the filter. Paths
//! never go on argv: a ring holds thousands of files.

use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
};

use anyhow::{Context as _, Result, bail};

pub(crate) fn output(dir: &Path, args: &[&str]) -> Result<Output> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .with_context(|| format!("cannot run git {args:?}"))
}

fn checked(out: Output, args: &[&str]) -> Result<Vec<u8>> {
    if !out.status.success() {
        bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// Run git, return stdout, fail with git's stderr.
pub(crate) fn run(dir: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(checked(output(dir, args)?, args)?)?)
}

/// Run git with `input` on stdin, fed from a thread so large inputs and large
/// outputs cannot deadlock on full pipes.
fn run_with_input(dir: &Path, args: &[&str], input: Vec<u8>) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run git {args:?}"))?;
    let mut stdin = child.stdin.take().context("no stdin for git")?;
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("git stdin writer panicked"))??;
    checked(out, args)
}

fn nul_joined(paths: &[String]) -> Vec<u8> {
    let mut input = paths.join("\0").into_bytes();
    input.push(0);
    input
}

/// Run a git command that takes pathspecs (checkout, add, ...) on `paths`,
/// literally and through stdin.
pub(crate) fn run_with_paths(dir: &Path, args: &[&str], paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut full = vec!["--literal-pathspecs"];
    full.extend(args);
    full.extend(["--pathspec-from-file=-", "--pathspec-file-nul"]);
    run_with_input(dir, &full, nul_joined(paths))?;
    Ok(())
}

pub(crate) fn config_get(dir: &Path, key: &str) -> Result<Option<String>> {
    let out = output(dir, &["config", "--get", key])?;
    let value = String::from_utf8(out.stdout)?.trim().to_owned();
    Ok((out.status.success() && !value.is_empty()).then_some(value))
}

fn nul_split(bytes: &[u8]) -> Result<Vec<String>> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| Ok(String::from_utf8(s.to_vec())?))
        .collect()
}

/// Tracked files under `pathspecs` (all when empty), as paths from the root.
pub(crate) fn tracked(root: &Path, pathspecs: &[&str]) -> Result<Vec<String>> {
    let mut args = vec!["ls-files", "-z", "--full-name", "--"];
    args.extend(pathspecs);
    nul_split(&checked(output(root, &args)?, &args)?)
}

/// Files git does not track, ignored ones included: plaintext all the same.
pub(crate) fn untracked(root: &Path) -> Result<Vec<String>> {
    let args = ["ls-files", "-z", "--full-name", "--others"];
    nul_split(&checked(output(root, &args)?, &args)?)
}

/// Subset of `paths` whose filter attribute is git-agecrypt, in one git call.
pub(crate) fn filtered(root: &Path, paths: &[String]) -> Result<HashSet<String>> {
    if paths.is_empty() {
        return Ok(HashSet::new());
    }
    let out = run_with_input(
        root,
        &["check-attr", "--stdin", "-z", "filter"],
        nul_joined(paths),
    )?;
    Ok(nul_split(&out)?
        .chunks(3)
        .filter(|t| t.len() == 3 && t[2] == "git-agecrypt")
        .map(|t| t[0].clone())
        .collect())
}

pub(crate) struct Entry {
    pub mode: String,
    pub oid: String,
}

/// Submodule entries point at commits of another repo: no blob to read.
const GITLINK_MODE: &str = "160000";

/// The whole index: path to mode and blob id, submodules left out.
pub(crate) fn index(root: &Path) -> Result<HashMap<String, Entry>> {
    let args = ["ls-files", "-s", "-z"];
    Ok(nul_split(&checked(output(root, &args)?, &args)?)?
        .into_iter()
        .filter_map(|e| {
            let (meta, path) = e.split_once('\t')?;
            let mut f = meta.split(' ');
            let mode = f.next()?.to_owned();
            let oid = f.next()?.to_owned();
            (mode != GITLINK_MODE).then(|| (path.to_owned(), Entry { mode, oid }))
        })
        .collect())
}

/// HEAD's tree: path to blob id, submodules left out. Empty before the first commit.
pub(crate) fn head(root: &Path) -> Result<HashMap<String, String>> {
    let args = ["ls-tree", "-r", "-z", "HEAD"];
    let out = output(root, &args)?;
    if !out.status.success() {
        return Ok(HashMap::new());
    }
    Ok(nul_split(&out.stdout)?
        .into_iter()
        .filter_map(|e| {
            let (meta, path) = e.split_once('\t')?;
            let mut f = meta.split(' ');
            let mode = f.next()?;
            let oid = f.nth(1)?;
            (mode != GITLINK_MODE).then(|| (path.to_owned(), oid.to_owned()))
        })
        .collect())
}

/// Blob contents by id, in one `cat-file --batch`.
pub(crate) fn blobs(root: &Path, oids: &[String]) -> Result<HashMap<String, Vec<u8>>> {
    if oids.is_empty() {
        return Ok(HashMap::new());
    }
    let raw = run_with_input(
        root,
        &["cat-file", "--batch"],
        (oids.join("\n") + "\n").into_bytes(),
    )?;
    let mut reader = BufReader::new(&raw[..]);
    let mut out = HashMap::new();
    let mut header = String::new();
    while reader.read_line(&mut header)? > 0 {
        let fields: Vec<&str> = header.split_whitespace().collect();
        let [oid, _kind, size] = fields[..] else {
            bail!("git cat-file: unexpected header {header:?}");
        };
        let mut data = vec![0u8; size.parse()?];
        reader.read_exact(&mut data)?;
        let mut newline = [0u8; 1];
        reader.read_exact(&mut newline)?;
        out.insert(oid.to_owned(), data);
        header.clear();
    }
    Ok(out)
}

/// Paths `git status` reports as changed, staged or untracked.
pub(crate) fn dirty(root: &Path) -> Result<HashSet<String>> {
    let args = ["status", "--porcelain", "-z"];
    parse_porcelain(&checked(output(root, &args)?, &args)?)
}

fn parse_porcelain(raw: &[u8]) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    let mut entries = raw.split(|&b| b == 0).filter(|s| !s.is_empty());
    while let Some(entry) = entries.next() {
        let entry = String::from_utf8(entry.to_vec())?;
        let Some((status, path)) = entry.split_at_checked(3) else {
            bail!("git status: unexpected entry {entry:?}");
        };
        out.insert(path.to_owned());
        // A rename or copy, staged (X) or in the worktree (Y, after
        // `add -N`), carries its original path as the next entry.
        if status[..2].contains(['R', 'C']) {
            let orig = entries
                .next()
                .context("git status: rename without its source")?;
            out.insert(String::from_utf8(orig.to_vec())?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porcelain_keeps_both_sides_of_staged_and_worktree_renames() {
        let raw = b"R  new\0old\0 R moved/b\0moved/a\0?? untracked\0";
        let paths = parse_porcelain(raw).unwrap();
        let mut paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        paths.sort();
        assert_eq!(paths, ["moved/a", "moved/b", "new", "old", "untracked"]);
    }

    #[test]
    fn porcelain_refuses_a_rename_without_its_source() {
        assert!(parse_porcelain(b"R  new\0").is_err());
    }
}
