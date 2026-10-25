// SPDX-License-Identifier: MPL-2.0

//! `on` / `off` / `check` / `sign` / `rekey` end to end: per-worktree unlock,
//! signed policy, and the attacks they close. Two rings with native keys, a
//! throwaway SSH signer, keys and trust anchor outside the repo.

// sh identityCommands, ssh-keygen signers and includeIf on POSIX paths.
#![cfg(unix)]

mod common;

use std::fs;

use common::*;
use duct::cmd;

#[test]
fn on_off_rewrite_stat_clean_files_and_drop_the_cache() {
    let r = Repo::new();
    assert!(r.on().contains("policy v1 signed by owner@test"));
    r.commit_secrets();
    assert!(r.staged(A).starts_with(MAGIC));
    assert!(r.cache_dir().exists());

    r.settle();
    r.ac_ok(&["off"]);
    assert!(r.read(A).starts_with(MAGIC));
    assert!(r.read(B).starts_with(MAGIC));
    assert!(!r.cache_dir().exists(), "the cache holds plaintext hashes");

    r.settle();
    r.on();
    assert_eq!(r.read(A), b"payload-a\n");
    assert_eq!(r.read(B), b"payload-b\n");
}

#[test]
fn on_refuses_uncommitted_ring_changes() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    r.ac_ok(&["off"]);
    r.write(A, "edited while locked\n");
    let out = r.on_in(&r.root);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("uncommitted changes"));
    assert_eq!(r.read(A), b"edited while locked\n");
}

#[test]
fn off_refuses_untracked_ring_files_ignored_ones_included() {
    let r = Repo::new();
    r.on();
    r.write("ring-a/new.txt", "never committed\n");
    r.write("ring-b/ignored.txt", "ignored\n");
    r.write(".gitignore", "ignored.txt\n");
    let out = r.ac(&["off"]);
    assert!(!out.status.success(), "off left plaintext behind");
    for path in ["ring-a/new.txt", "ring-b/ignored.txt"] {
        assert!(stderr(&out).contains(path), "{}", stderr(&out));
    }
    fs::remove_file(r.root.join("ring-a/new.txt")).unwrap();
    fs::remove_file(r.root.join("ring-b/ignored.txt")).unwrap();
    r.ac_ok(&["off"]);
}

#[test]
fn unlock_stays_in_one_worktree_and_children_are_born_locked() {
    let r = Repo::new();
    let wt = r.outside("wt");
    r.git_ok(&["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "wt"]);
    ok(r.on_in(&wt), "on in the linked worktree");
    fs::create_dir_all(wt.join("ring-a")).unwrap();
    fs::write(wt.join(A), "payload-a\n").unwrap();
    ok(r.git_in(&wt, &["add", A]), "add");
    ok(r.git_in(&wt, &["commit", "-q", "-m", "secret"]), "commit");
    assert_eq!(fs::read(wt.join(A)).unwrap(), b"payload-a\n");

    let child = r.outside("child");
    ok(
        r.git_in(
            &wt,
            &[
                "worktree",
                "add",
                "-q",
                child.to_str().unwrap(),
                "-b",
                "child",
            ],
        ),
        "child worktree",
    );
    assert!(fs::read(child.join(A)).unwrap().starts_with(MAGIC));

    r.git_ok(&["merge", "-q", "--ff-only", "wt"]);
    assert!(
        r.read(A).starts_with(MAGIC),
        "the main worktree stays locked"
    );
}

#[test]
fn on_refuses_an_unsigned_recipient() {
    let r = Repo::new();
    r.add_unsigned_recipient("ring-a/**");
    let out = r.on_in(&r.root);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does not match"), "{}", stderr(&out));
}

#[test]
fn a_pulled_recipient_blocks_encryption_and_the_commit() {
    let r = Repo::new();
    r.on();
    r.add_unsigned_recipient("ring-a/**");
    r.write(A, "payload\n");
    let add = r.git(&["add", A]);
    assert!(!add.status.success(), "clean must refuse to encrypt");
    assert!(
        stderr(&add).contains("refusing to encrypt"),
        "{}",
        stderr(&add)
    );
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("changed since git-agecrypt on"));
}

#[test]
fn a_pulled_policy_keeps_reset_and_status_working() {
    let r = Repo::new();
    r.use_env_key();
    ok(r.on_key(), "git-agecrypt on");
    r.commit_secrets();
    // B as a keyless pull leaves it: the index ciphertext on disk.
    fs::remove_file(r.root.join(B)).unwrap();
    r.git_ok(&["checkout", "--", B]);
    assert!(r.read(B).starts_with(MAGIC));
    r.add_unsigned_recipient("ring-a/**");
    // Stale stat: git cleans both files again.
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    for rel in [A, B] {
        fs::File::open(r.root.join(rel))
            .unwrap()
            .set_modified(past)
            .unwrap();
    }
    r.git_ok(&["reset", "-q"]);
    assert_eq!(
        r.git_ok(&["status", "--porcelain"]),
        " M git-agecrypt.toml\n"
    );
    // Nor does a policy that no longer parses stop them.
    let toml = fs::read_to_string(r.root.join("git-agecrypt.toml")).unwrap();
    r.write("git-agecrypt.toml", &format!("{toml}\n[after]\n"));
    fs::File::open(r.root.join(A))
        .unwrap()
        .set_modified(past)
        .unwrap();
    r.git_ok(&["reset", "-q"]);
    r.write(A, "new while the policy moved\n");
    let add = r.git(&["add", A]);
    assert!(!add.status.success(), "clean must still refuse to encrypt");
    assert!(
        stderr(&add).contains("refusing to encrypt"),
        "{}",
        stderr(&add)
    );
}

#[test]
fn a_nested_gitattributes_cannot_switch_a_ring_off() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    r.write("ring-a/.gitattributes", "* -filter -diff\n");
    let attr = r.git_ok(&["check-attr", "filter", A]);
    assert_eq!(attr.trim(), format!("{A}: filter: git-agecrypt"));
    r.write(A, "edited\n");
    r.git_ok(&["add", A, "ring-a/.gitattributes"]);
    assert!(r.staged(A).starts_with(MAGIC));
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("ring-a/.gitattributes: would override the ring filter"));
}

#[test]
fn rollback_to_an_older_signed_policy_is_refused() {
    let r = Repo::new();
    r.on();
    r.add_unsigned_recipient("ring-b/**");
    r.ac_ok(&["sign"]);
    assert!(r.on().contains("policy v2"));
    r.git_ok(&["checkout", "HEAD", "--", "git-agecrypt.toml"]);
    let out = r.on_in(&r.root);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("rollback"), "{}", stderr(&out));
}

#[test]
fn home_from_the_environment_does_not_move_the_trust_anchor() {
    let r = Repo::new();
    let fake = r.outside("fake-home");
    fs::create_dir(&fake).unwrap();
    let out = cmd(bin(), ["on"])
        .dir(&r.root)
        .env("HOME", &fake)
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap();
    assert!(
        !stderr(&out).contains(fake.to_str().unwrap()),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_ring_must_be_a_whole_directory() {
    let r = Repo::new();
    for name in [".gitattributes", "git-agecrypt.toml"] {
        let text = fs::read_to_string(r.root.join(name)).unwrap();
        r.write(name, &text.replace("ring-a/**", "ring-a/**/*.csv"));
    }
    let out = r.ac(&["sign"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("rings must be whole directories"));
}

#[test]
fn every_file_type_inside_a_ring_is_encrypted() {
    let r = Repo::new();
    r.on();
    r.write("ring-a/vendors.xlsx", "PK spreadsheet");
    r.write("ring-a/mapping.json", "{\"V-0007\": \"x\"}\n");
    r.git_ok(&["add", "ring-a"]);
    assert!(r.staged("ring-a/vendors.xlsx").starts_with(MAGIC));
    assert!(r.staged("ring-a/mapping.json").starts_with(MAGIC));
    r.ac_ok(&["check", "--staged"]);
}

#[cfg(unix)]
#[test]
fn a_symlink_inside_a_ring_is_refused() {
    let r = Repo::new();
    r.on();
    r.write("outside.csv", "secret\n");
    fs::create_dir_all(r.root.join("ring-a")).unwrap();
    std::os::unix::fs::symlink("../outside.csv", r.root.join("ring-a/link.csv")).unwrap();
    r.git_ok(&["add", "ring-a/link.csv"]);
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("symlink inside a ring"));
}

#[test]
fn check_skips_paths_missing_from_the_index() {
    // Nothing is committed for them: a hook runner may still pass them along.
    let r = Repo::new();
    r.write("ring-a/untracked.csv", "plain\n");
    r.ac_ok(&["check", "ring-a/untracked.csv"]);
}

#[test]
fn check_reads_paths_literally() {
    let r = Repo::new();
    r.write("ring-a/a*.csv", "plain\n");
    r.write("ring-a/ab.csv", "plain\n");
    r.git_ok(&["add", "--", "ring-a/ab.csv"]);
    let check = r.ac(&["check", "ring-a/a*.csv"]);
    assert!(
        check.status.success(),
        "the unstaged a*.csv must not match ab.csv"
    );
}

#[test]
fn plaintext_staged_in_a_locked_worktree_is_refused() {
    let r = Repo::new();
    r.write(A, "payload-a\n");
    r.git_ok(&["add", A]);
    let check = r.ac(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(stderr(&check).contains("staged blob is not age ciphertext"));
}

#[test]
fn rekey_moves_existing_files_to_the_new_recipients() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    let pub_c = age_key(&r.outside("c.key"));
    let toml = fs::read_to_string(r.root.join("git-agecrypt.toml")).unwrap();
    let pub_a = toml.split('"').nth(3).unwrap().to_owned();
    r.write("git-agecrypt.toml", &toml.replace(&pub_a, &pub_c));
    r.git_ok(&[
        "config",
        "--add",
        "git-agecrypt.config.identityCommand",
        &format!("cat '{}'", r.outside("c.key").display()),
    ]);
    r.ac_ok(&["sign"]);
    r.on();
    r.ac_ok(&["rekey", "ring-a"]);
    let blob = r.staged(A);
    let opens = |key: &str| {
        cmd!("age", "-d", "-i", r.outside(key))
            .stdin_bytes(blob.clone())
            .stdout_capture()
            .stderr_capture()
            .unchecked()
            .run()
            .unwrap()
            .status
            .success()
    };
    assert!(opens("c.key"), "rekeyed blob must open with the new key");
    assert!(!opens("a.key"), "the removed key must no longer open it");
}

#[test]
fn diffs_show_plaintext_only_in_the_unlocked_worktree() {
    let r = Repo::new();
    r.on();
    r.commit_secrets();
    assert!(
        r.git_ok(&["log", "-p", "-1", "--", A])
            .contains("payload-a")
    );
    let wt = r.outside("wt");
    r.git_ok(&["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "wt"]);
    let locked = ok(r.git_in(&wt, &["log", "-p", "-1", "--", A]), "log");
    assert!(!locked.contains("payload-a"), "{locked}");
}

#[test]
fn a_file_larger_than_a_pkt_line_round_trips() {
    let r = Repo::new();
    r.on();
    let big: String = (0..20_000).map(|i| format!("line {i}\n")).collect();
    assert!(big.len() > 3 * 65516);
    r.write("ring-a/big.txt", &big);
    r.git_ok(&["add", "ring-a/big.txt"]);
    r.git_ok(&["commit", "-q", "-m", "big"]);
    assert!(r.staged("ring-a/big.txt").starts_with(MAGIC));
    r.ac_ok(&["off"]);
    assert!(r.read("ring-a/big.txt").starts_with(MAGIC));
    r.on();
    assert_eq!(r.read("ring-a/big.txt"), big.as_bytes());
}

#[test]
fn sign_needs_ssh_signing() {
    let r = Repo::new();
    r.git_ok(&["config", "gpg.format", "openpgp"]);
    let out = r.ac(&["sign"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("gpg.format must be ssh"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn on_refuses_to_overwrite_an_unmanaged_info_attributes() {
    let r = Repo::new();
    let info = r.root.join(".git/info/attributes");
    fs::create_dir_all(info.parent().unwrap()).unwrap();
    fs::write(&info, "*.bin binary\n").unwrap();
    let out = r.on_in(&r.root);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not managed by git-agecrypt"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fs::read_to_string(&info).unwrap(), "*.bin binary\n");
}

#[test]
fn verify_and_on_need_a_trust_anchor() {
    let r = Repo::new();
    fs::remove_file(r.trust().join("allowed_signers")).unwrap();
    for out in [
        r.ac(&["verify", "--trust", r.trust().to_str().unwrap()]),
        r.on_in(&r.root),
    ] {
        assert!(!out.status.success());
        assert!(stderr(&out).contains("no trust anchor"), "{}", stderr(&out));
    }
}
