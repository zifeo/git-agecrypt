// SPDX-License-Identifier: MPL-2.0

//! The single-process filter, and regressions for the review of this fork:
//! every worktree that is not unlocked must fail closed, and the unlocked one
//! must not be tricked into encrypting less than the signed policy says.

// sh identityCommands, ssh-keygen signers and includeIf on POSIX paths.
#![cfg(unix)]

mod common;

use std::fs;

use common::*;
use duct::cmd;

fn identity_calls(r: &Repo) -> usize {
    fs::read_to_string(r.outside("calls"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

fn set_identity_command(r: &Repo, command: &str) {
    r.git_ok(&[
        "config",
        "--replace-all",
        "git-agecrypt.config.identityCommand",
        command,
    ]);
}

fn keys(r: &Repo) -> String {
    format!(
        "'{}' '{}'",
        r.outside("a.key").display(),
        r.outside("b.key").display()
    )
}

#[test]
fn a_checkout_loads_identities_once_for_every_file() {
    let r = Repo::new();
    r.on();
    for i in 0..10 {
        r.write(&format!("ring-a/f{i}.txt"), &format!("payload {i}\n"));
    }
    r.git_ok(&["add", "ring-a"]);
    r.git_ok(&["commit", "-q", "-m", "ten"]);
    let calls = r.outside("calls");
    set_identity_command(
        &r,
        &format!("echo call >> '{}' && cat {}", calls.display(), keys(&r)),
    );
    fs::remove_dir_all(r.root.join("ring-a")).unwrap();
    r.git_ok(&["checkout", "--", "ring-a"]);
    for i in 0..10 {
        assert_eq!(
            r.read(&format!("ring-a/f{i}.txt")),
            format!("payload {i}\n").as_bytes()
        );
    }
    assert_eq!(
        identity_calls(&r),
        1,
        "identityCommand must run once per git command"
    );
}

#[test]
fn a_failing_identity_command_fails_the_checkout_closed() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    set_identity_command(&r, "exit 3");
    fs::remove_file(r.root.join(A)).unwrap();
    assert!(!r.git(&["checkout", "--", A]).status.success());
    if r.root.join(A).exists() {
        assert_ne!(r.read(A), b"payload-a\n", "plaintext written without a key");
    }
}

/// F1: a moved repo no longer matches its include. It must fail closed, and
/// a plain `on` must re-pin it.
#[test]
fn a_moved_repo_fails_closed_then_on_repins_it() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    let moved = r.outside("moved");
    fs::rename(&r.root, &moved).unwrap();
    fs::write(moved.join(A), "edited after the move\n").unwrap();
    let commit = r.git_in(&moved, &["commit", "-q", "-am", "leak?"]);
    assert!(!commit.status.success(), "plaintext must not be committed");
    let head = r.git_in(&moved, &["cat-file", "blob", &format!("HEAD:{A}")]);
    assert!(head.stdout.starts_with(MAGIC));

    fs::write(moved.join(A), "payload-a\n").unwrap();
    ok(r.on_in(&moved), "on after the move");
    fs::write(moved.join(A), "edited after the move\n").unwrap();
    ok(
        r.git_in(&moved, &["commit", "-q", "-am", "edit"]),
        "commit after on",
    );
    let head = r.git_in(&moved, &["cat-file", "blob", &format!("HEAD:{A}")]);
    assert!(head.stdout.starts_with(MAGIC));
}

/// F2: replacing an `init` unlock must not leave other worktrees able to
/// commit their plaintext.
#[test]
fn an_init_unlock_is_replaced_by_the_locked_baseline() {
    let r = Repo::new();
    r.ac_ok(&["init"]);
    r.commit_secrets();
    assert_eq!(r.read(A), b"payload-a\n");
    let wt = r.outside("wt");
    r.git_ok(&["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "wt"]);
    ok(r.on_in(&wt), "on in the linked worktree");
    r.write(A, "edited in main\n");
    assert!(!r.git(&["commit", "-q", "-am", "leak?"]).status.success());
    let head = r.git(&["cat-file", "blob", &format!("HEAD:{A}")]);
    assert!(head.stdout.starts_with(MAGIC));
}

/// F3: a genuinely signed policy for another repo id is refused.
#[test]
fn a_foreign_policy_id_is_refused() {
    let r = Repo::new();
    r.on();
    let toml = fs::read_to_string(r.root.join("git-agecrypt.toml")).unwrap();
    let foreign: String = toml
        .lines()
        .map(|l| {
            if l.starts_with("id") {
                "id = \"00000000000000000000000000000000\"\n".to_owned()
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    r.write("git-agecrypt.toml", &foreign);
    r.ac_ok(&["sign"]);
    let out = r.on_in(&r.root);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("foreign policy"), "{}", stderr(&out));
}

/// F4: git runs the canonical binary that passed the guard, not a link to it.
#[cfg(unix)]
#[test]
fn the_filter_runs_the_checked_binary_not_a_link() {
    let r = Repo::new();
    let link = r.root.join("gac");
    std::os::unix::fs::symlink(bin(), &link).unwrap();
    ok(
        run_in(
            &r.root,
            &link,
            &["on", "--trust", r.trust().to_str().unwrap()],
        ),
        "on through a link",
    );
    let process = r.git_ok(&["config", "--get", "filter.git-agecrypt.process"]);
    let canonical = fs::canonicalize(bin()).unwrap();
    assert!(process.contains(canonical.to_str().unwrap()), "{process}");
    assert!(!process.contains("/gac"), "{process}");
}

/// F5: a re-pin that drops a ring turns its files back into ciphertext, and
/// plaintext where HEAD held ciphertext is refused.
#[test]
fn dropping_a_ring_turns_its_files_back_into_ciphertext() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    for name in [".gitattributes", "git-agecrypt.toml"] {
        let text = fs::read_to_string(r.root.join(name)).unwrap();
        let kept: String = text
            .lines()
            .filter(|l| !l.contains("ring-b"))
            .map(|l| format!("{l}\n"))
            .collect();
        r.write(name, &kept);
    }
    r.ac_ok(&["sign"]);
    r.on();
    assert!(
        r.read(B).starts_with(MAGIC),
        "ring-b must not stay plaintext"
    );
    r.write(B, "plaintext now\n");
    r.git_ok(&["add", B]);
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("ciphertext in HEAD, plaintext now"));
}

/// F6: decrypted ring content copied out of the rings is refused.
#[test]
fn a_copy_out_of_a_ring_is_refused() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    r.write("notes/copy.txt", "payload-a\n");
    r.git_ok(&["add", "notes/copy.txt"]);
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("a copy out of a ring"));
}

/// F7: a locked worktree (an agent's) can neither stage nor commit plaintext
/// into a ring, even through plumbing.
#[test]
fn a_locked_worktree_cannot_commit_plaintext_into_a_ring() {
    let r = Repo::new();
    r.on();
    let wt = r.outside("agent");
    r.git_ok(&["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "agent"]);
    fs::create_dir_all(wt.join("ring-a")).unwrap();
    fs::write(wt.join("ring-a/report.txt"), "plain\n").unwrap();
    assert!(
        !r.git_in(&wt, &["add", "ring-a/report.txt"])
            .status
            .success()
    );
    let oid = ok(
        r.git_in(
            &wt,
            &["hash-object", "-w", "--no-filters", "ring-a/report.txt"],
        ),
        "hash-object",
    );
    let info = format!("100644,{},ring-a/report.txt", oid.trim());
    ok(
        r.git_in(&wt, &["update-index", "--add", "--cacheinfo", &info]),
        "update-index",
    );
    assert!(
        !r.git_in(&wt, &["commit", "-q", "-m", "leak?"])
            .status
            .success()
    );
}

/// F9: an undecryptable blob makes `on` fail without deleting anything, and
/// leaves the worktree locked with ciphertext on disk.
#[test]
fn a_failed_on_leaves_the_worktree_locked_and_whole() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    let stranger = age_key(&r.outside("stranger.key"));
    let foreign = cmd!("age", "-r", &stranger)
        .stdin_bytes(b"not for us\n".to_vec())
        .stdout_capture()
        .run()
        .unwrap()
        .stdout;
    // Another key holder's blob, written raw as a pull would bring it: `git
    // add` refuses ciphertext that neither git nor a local key knows.
    fs::write(r.root.join("ring-a/foreign.txt"), &foreign).unwrap();
    let oid = r.git_ok(&["hash-object", "-w", "--no-filters", "ring-a/foreign.txt"]);
    let entry = format!("100644,{},ring-a/foreign.txt", oid.trim());
    r.git_ok(&["update-index", "--add", "--cacheinfo", &entry]);
    r.git_ok(&["commit", "-q", "-m", "foreign"]);
    r.ac_ok(&["off"]);
    assert!(!r.on_in(&r.root).status.success());
    for rel in [A, B, "ring-a/foreign.txt"] {
        assert!(
            r.read(rel).starts_with(MAGIC),
            "{rel}: must be present ciphertext"
        );
    }
    let pinned = r.git(&["config", "--get", "git-agecrypt.policy.pinned"]);
    assert!(!pinned.status.success(), "the worktree must stay locked");
}

/// F10: an identity that errors (here a plugin that always fails) does not
/// stop the working key listed after it.
#[cfg(unix)]
#[test]
fn a_failing_identity_does_not_block_the_next_one() {
    use std::os::unix::fs::PermissionsExt;
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    let plugins = r.outside("plugins");
    fs::create_dir(&plugins).unwrap();
    let plugin = plugins.join("age-plugin-broken");
    fs::write(&plugin, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
    let broken = age::plugin::Identity::default_for_plugin("broken").to_string();
    set_identity_command(&r, &format!("echo '{broken}' && cat {}", keys(&r)));
    fs::remove_file(r.root.join(A)).unwrap();
    let path = format!("{}:{}", plugins.display(), std::env::var("PATH").unwrap());
    let out = cmd("git", ["checkout", "--", A])
        .dir(&r.root)
        .env("PATH", path)
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(r.read(A), b"payload-a\n");
}

/// F13: a ring file replaced by a symlink (a type change) is refused.
#[cfg(unix)]
#[test]
fn a_type_change_to_a_symlink_is_refused() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    fs::remove_file(r.root.join(A)).unwrap();
    std::os::unix::fs::symlink("../outside.txt", r.root.join(A)).unwrap();
    r.git_ok(&["add", A]);
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("symlink inside a ring"));
}

/// F15: rekey in a locked worktree refuses instead of claiming success.
#[test]
fn rekey_refuses_in_a_locked_worktree() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    r.ac_ok(&["off"]);
    let out = r.ac(&["rekey"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("needs this worktree unlocked"));
}

/// B5: an age first line in front of plaintext is not ciphertext. Unlocked,
/// no key here opens it; locked, git never had that blob: both refuse it.
#[test]
fn a_forged_age_header_is_refused_locked_and_unlocked() {
    let r = Repo::new();
    r.on();
    let forged = "age-encryption.org/v1\nMARKER plaintext\n";
    r.write("ring-a/forged.txt", forged);
    let out = r.git(&["add", "ring-a/forged.txt"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("neither git nor a key here knows it"),
        "{}",
        stderr(&out)
    );
    let wt = r.outside("wt");
    r.git_ok(&["worktree", "add", "-q", "--detach", wt.to_str().unwrap()]);
    fs::create_dir_all(wt.join("ring-a")).unwrap();
    fs::write(wt.join("ring-a/forged.txt"), forged).unwrap();
    let out = r.git_in(&wt, &["add", "ring-a/forged.txt"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("this worktree is locked"),
        "{}",
        stderr(&out)
    );
}

/// B2: a submodule bump has no blob to read; the gate lets it through.
#[test]
fn a_submodule_bump_commits_in_an_unlocked_worktree() {
    let r = Repo::new();
    r.on();
    let head = r.git_ok(&["rev-parse", "HEAD"]);
    let entry = format!("160000,{},vendored", head.trim());
    r.git_ok(&["update-index", "--add", "--cacheinfo", &entry]);
    r.git_ok(&["commit", "-q", "-m", "bump"]);
}

/// F6: a merge commit runs the gate too (pre-merge-commit), so a branch
/// carrying a plaintext ring blob cannot be merged in.
#[test]
fn a_merge_bringing_plaintext_into_a_ring_is_refused() {
    let r = Repo::new();
    r.on();
    let wt = r.outside("wt");
    r.git_ok(&["worktree", "add", "-q", "-b", "side", wt.to_str().unwrap()]);
    let raw = r.outside("plain.txt");
    fs::write(&raw, "MARKER\n").unwrap();
    let oid = ok(
        r.git_in(
            &wt,
            &["hash-object", "-w", "--no-filters", raw.to_str().unwrap()],
        ),
        "hash-object",
    );
    let entry = format!("100644,{},ring-a/leak.txt", oid.trim());
    ok(
        r.git_in(&wt, &["update-index", "--add", "--cacheinfo", &entry]),
        "update-index",
    );
    ok(
        r.git_in(&wt, &["commit", "-q", "--no-verify", "-m", "leak"]),
        "commit",
    );
    ok(
        r.git_in(&wt, &["checkout", "-q", "--detach", "main"]),
        "checkout",
    );
    let out = r.git_in(&wt, &["merge", "--no-ff", "-m", "merge", "side"]);
    assert!(!out.status.success(), "the merge must be refused");
    assert!(
        stderr(&out).contains("not age ciphertext"),
        "{}",
        stderr(&out)
    );
}

/// H1: `sign` reads `~/` in user.signingkey the way git does.
#[test]
fn sign_expands_a_tilde_signing_key_like_git() {
    let r = Repo::new();
    r.git_ok(&["config", "user.signingkey", "~/owner"]);
    r.add_unsigned_recipient("ring-a/**");
    let out = cmd(bin(), ["sign"])
        .dir(&r.root)
        .env("HOME", r.dir.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    r.ac_ok(&["verify", "--trust", r.trust().to_str().unwrap()]);
}

/// H2: `off` turns a read-only ring file back into ciphertext too.
#[cfg(unix)]
#[test]
fn off_relocks_a_read_only_ring_file() {
    use std::os::unix::fs::PermissionsExt;
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    r.settle();
    fs::set_permissions(r.root.join(A), fs::Permissions::from_mode(0o444)).unwrap();
    r.ac_ok(&["off"]);
    assert!(
        r.read(A).starts_with(MAGIC),
        "{A} still plaintext after off"
    );
}

/// H3: an allowed_signers line may list several principals for one key.
#[test]
fn a_key_shared_by_several_principals_verifies() {
    let r = Repo::new();
    let anchor = r.trust().join("allowed_signers");
    let line = fs::read_to_string(&anchor).unwrap();
    fs::write(
        &anchor,
        line.replacen("owner@test", "owner@test,backup@test", 1),
    )
    .unwrap();
    assert!(r.on().contains("signed by owner@test"));
}

/// H4: the include pattern is escaped: a repo moved under a path with
/// spaces and glob characters re-pins and decrypts there.
#[test]
fn a_repo_moved_under_glob_characters_repins() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    let moved = r.outside("re po[1]*?");
    fs::rename(&r.root, &moved).unwrap();
    ok(r.on_in(&moved), "on in the moved repo");
    let pinned = r.git_in(&moved, &["config", "--get", "git-agecrypt.policy.pinned"]);
    assert!(pinned.status.success(), "the moved repo must be pinned");
    fs::write(moved.join("ring-a/more.txt"), "more\n").unwrap();
    ok(r.git_in(&moved, &["add", "ring-a/more.txt"]), "add");
    ok(r.git_in(&moved, &["commit", "-q", "-m", "more"]), "commit");
    assert_eq!(fs::read(moved.join(A)).unwrap(), b"payload-a\n");
}
