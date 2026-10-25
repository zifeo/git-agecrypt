// SPDX-License-Identifier: MPL-2.0

//! `check`: the commit gate, a config hook in every worktree of the clone.
//! Rejects plaintext under a ring, anything inside a ring that is not
//! encrypted (symlinks, nested .gitattributes), plaintext where HEAD held
//! ciphertext (a ring dropped), copies of ring plaintext outside the rings,
//! and in an unlocked worktree a policy that changed since `on` pinned it.

use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::{age::is_ciphertext, ctx::Context, git::Repository, gitcli, policy};

const SYMLINK_MODE: &str = "120000";

pub(crate) fn check<C: Context>(ctx: &C, staged: bool, paths: Vec<PathBuf>) -> Result<()> {
    let root = ctx.repo().workdir().to_path_buf();
    let paths: Vec<String> = if staged {
        // Everything but deletions: a type change to a symlink must be seen too.
        let out = gitcli::run(
            &root,
            &["diff", "--cached", "--name-only", "--diff-filter=d", "-z"],
        )?;
        out.split('\0')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    };
    let failures = problems(ctx, &paths)?;
    for failure in &failures {
        eprintln!("{failure}");
    }
    if !failures.is_empty() {
        bail!("{} path(s) must not be committed as staged", failures.len());
    }
    Ok(())
}

fn problems<C: Context>(ctx: &C, paths: &[String]) -> Result<Vec<String>> {
    let root = ctx.repo().workdir().to_path_buf();
    let mut out = vec![];
    if let Some(pinned) = ctx.pinned_policy()?
        && policy::digest(&root)? != pinned
    {
        out.push("rings or recipients changed since git-agecrypt on: review, then on again".into());
    }
    let rings = policy::ring_dirs_if_any(&root)?;
    let index = gitcli::index(&root)?;
    // A path missing from the index commits nothing: there is no blob to check.
    let paths: Vec<String> = paths
        .iter()
        .filter(|p| index.contains_key(*p))
        .cloned()
        .collect();
    let encrypted = gitcli::filtered(&root, &paths)?;
    let head = gitcli::head(&root)?;
    let mut oids: Vec<String> = paths.iter().map(|p| index[p].oid.clone()).collect();
    oids.extend(paths.iter().filter_map(|p| head.get(p).cloned()));
    let blobs = gitcli::blobs(&root, &oids)?;
    let cached = ctx.cached_plaintext_hashes()?;

    for path in &paths {
        let entry = &index[path];
        let blob = &blobs[&entry.oid];
        let link = entry.mode == SYMLINK_MODE;
        let is_age = is_ciphertext(blob);
        let in_ring = rings.iter().any(|d| path.starts_with(d.as_str()));
        let reason = if in_ring && path.ends_with("/.gitattributes") {
            Some("would override the ring filter")
        } else if in_ring && link {
            Some("symlink inside a ring: git never filters links")
        } else if in_ring && !encrypted.contains(path) {
            Some("inside a ring but not encrypted")
        } else if encrypted.contains(path) && !link && !is_age {
            Some("staged blob is not age ciphertext")
        } else if !is_age && head.get(path).is_some_and(|h| is_ciphertext(&blobs[h])) {
            Some("ciphertext in HEAD, plaintext now: its ring was dropped or the file moved")
        } else if !is_age && !blob.is_empty() && cached.contains(blake3::hash(blob).as_bytes()) {
            Some("same content as a decrypted ring file: a copy out of a ring")
        } else {
            None
        };
        if let Some(reason) = reason {
            out.push(format!("{path}: {reason}"));
        }
    }
    Ok(out)
}
