// SPDX-License-Identifier: MPL-2.0

//! The key only in `GIT_AGECRYPT_IDENTITY`, for the one command a secret
//! manager filled it for: `on` decrypts, every later git command runs keyless.
#![cfg(unix)]

mod common;

use common::*;

fn unlocked_with_secrets() -> Repo {
    let r = Repo::new();
    r.use_env_key();
    ok(r.on_key(), "git-agecrypt on");
    r.commit_secrets();
    r
}

#[test]
fn on_without_a_key_refuses_and_stays_locked() {
    let r = unlocked_with_secrets();
    r.ac_ok(&["off"]);
    let out = r.on_in(&r.root);
    assert!(!out.status.success(), "on without any key must fail");
    assert!(stderr(&out).contains(IDENTITY_ENV), "{}", stderr(&out));
    assert!(r.read(A).starts_with(MAGIC), "a refused on left plaintext");
    ok(r.on_key(), "git-agecrypt on with the key");
    assert_eq!(r.read(A), b"payload-a\n");
}

#[test]
fn edits_commit_without_a_key() {
    let r = unlocked_with_secrets();
    let before = r.staged(A);
    r.write(A, "edited\n");
    r.git_ok(&["add", A]);
    r.git_ok(&["commit", "-q", "-m", "edit"]);
    let after = r.staged(A);
    assert!(
        after.starts_with(MAGIC),
        "an edit reached the index as plaintext"
    );
    assert_ne!(after, before, "the edit was not encrypted anew");
    assert!(r.git_ok(&["status", "--porcelain"]).is_empty());
}

#[test]
fn a_keyless_checkout_keeps_ciphertext_until_on() {
    let r = unlocked_with_secrets();
    r.git_ok(&["checkout", "-q", "-b", "side"]);
    r.write(A, "side\n");
    r.git_ok(&["commit", "-q", "-am", "side"]);
    let out = r.git(&["checkout", "-q", "main"]);
    ok(out.clone(), "keyless checkout");
    // The notice is for a terminal: captured stderr, as gitleaks reads it, stays empty.
    assert!(stderr(&out).is_empty(), "{}", stderr(&out));
    assert_eq!(
        r.read(A),
        r.staged(A),
        "the file is not the index ciphertext"
    );
    assert!(
        r.git_ok(&["status", "--porcelain"]).is_empty(),
        "ciphertext looks dirty"
    );
    ok(r.on_key(), "git-agecrypt on again");
    assert_eq!(r.read(A), b"payload-a\n");
    assert!(r.git_ok(&["status", "--porcelain"]).is_empty());
}

#[test]
fn a_keyless_diff_names_the_missing_key() {
    let r = unlocked_with_secrets();
    r.write(A, "second\n");
    r.git_ok(&["commit", "-q", "-am", "second"]);
    let out = r.git(&["log", "-p", "-1", "--", A]);
    assert!(stderr(&out).is_empty(), "{}", stderr(&out));
    let keyless = ok(out, "keyless git log");
    assert!(keyless.contains("no key in this git command"), "{keyless}");
    let keyed = ok(
        r.git_key(&["log", "-p", "-1", "--", A]),
        "git log with the key",
    );
    assert!(keyed.contains("+second"), "{keyed}");
}
