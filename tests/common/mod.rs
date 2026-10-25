// SPDX-License-Identifier: MPL-2.0

//! Shared fixture: a repo with two rings, native keys, a throwaway SSH
//! signer, keys and trust anchor outside the repo.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, SystemTime};

use age::secrecy::ExposeSecret;
use assert_fs::TempDir;
use duct::cmd;

pub const A: &str = "ring-a/secret.txt";
pub const B: &str = "ring-b/secret.txt";
pub const MAGIC: &[u8] = b"age-encryption.org/v1";

pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_git-agecrypt"))
}

pub struct Repo {
    pub dir: TempDir,
    pub root: PathBuf,
}

pub fn run_in<P: duct::IntoExecutablePath>(dir: &Path, program: P, args: &[&str]) -> Output {
    cmd(program, args)
        .dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run()
        .unwrap()
}

pub fn ok(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn age_key(path: &Path) -> String {
    let id = age::x25519::Identity::generate();
    fs::write(path, format!("{}\n", id.to_string().expose_secret())).unwrap();
    id.to_public().to_string()
}

impl Repo {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        let repo = Self { dir, root };
        repo.git_ok(&["init", "-q", "--initial-branch=main"]);
        let owner = repo.outside("owner");
        ok(
            run_in(
                repo.dir.path(),
                "ssh-keygen",
                &[
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "owner",
                    "-f",
                    owner.to_str().unwrap(),
                ],
            ),
            "ssh-keygen",
        );
        let pubkey = fs::read_to_string(owner.with_extension("pub")).unwrap();
        let fields: Vec<&str> = pubkey.split_whitespace().collect();
        fs::create_dir(repo.trust()).unwrap();
        fs::write(
            repo.trust().join("allowed_signers"),
            format!("owner@test {} {}\n", fields[0], fields[1]),
        )
        .unwrap();
        let pub_a = age_key(&repo.outside("a.key"));
        let pub_b = age_key(&repo.outside("b.key"));
        let identity = format!(
            "cat '{}' '{}'",
            repo.outside("a.key").display(),
            repo.outside("b.key").display()
        );
        for (key, value) in [
            ("user.email", "test@example.com"),
            ("user.name", "Test"),
            ("commit.gpgsign", "false"),
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", "ssh-keygen"),
            ("user.signingkey", owner.to_str().unwrap()),
            ("git-agecrypt.config.identityCommand", identity.as_str()),
        ] {
            repo.git_ok(&["config", key, value]);
        }
        repo.write(
            ".gitattributes",
            "ring-a/** filter=git-agecrypt diff=git-agecrypt\nring-b/** filter=git-agecrypt diff=git-agecrypt\n",
        );
        repo.write(
            "git-agecrypt.toml",
            &format!("[config]\n\"ring-a/**\" = [\"{pub_a}\"]\n\"ring-b/**\" = [\"{pub_b}\"]\n"),
        );
        repo.ac_ok(&["sign"]);
        repo.git_ok(&["add", ".gitattributes", "git-agecrypt.toml"]);
        repo.git_ok(&["commit", "-q", "-m", "rings"]);
        repo
    }

    pub fn outside(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn trust(&self) -> PathBuf {
        self.outside("trust")
    }

    pub fn git_in(&self, dir: &Path, args: &[&str]) -> Output {
        run_in(dir, "git", args)
    }

    pub fn git(&self, args: &[&str]) -> Output {
        self.git_in(&self.root, args)
    }

    pub fn git_ok(&self, args: &[&str]) -> String {
        ok(self.git(args), &format!("git {args:?}"))
    }

    pub fn ac_in(&self, dir: &Path, args: &[&str]) -> Output {
        run_in(dir, bin(), args)
    }

    pub fn ac(&self, args: &[&str]) -> Output {
        self.ac_in(&self.root, args)
    }

    pub fn ac_ok(&self, args: &[&str]) -> String {
        ok(self.ac(args), &format!("git-agecrypt {args:?}"))
    }

    pub fn on_in(&self, dir: &Path) -> Output {
        self.ac_in(dir, &["on", "--trust", self.trust().to_str().unwrap()])
    }

    pub fn on(&self) -> String {
        ok(self.on_in(&self.root), "git-agecrypt on")
    }

    pub fn write(&self, rel: &str, contents: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
    }

    pub fn read(&self, rel: &str) -> Vec<u8> {
        fs::read(self.root.join(rel)).unwrap()
    }

    pub fn staged(&self, rel: &str) -> Vec<u8> {
        self.git(&["cat-file", "blob", &format!(":{rel}")]).stdout
    }

    pub fn commit_secrets(&self) {
        self.write(A, "payload-a\n");
        self.write(B, "payload-b\n");
        self.git_ok(&["add", A, B]);
        self.git_ok(&["commit", "-q", "-m", "secrets"]);
    }

    /// Stat-clean, non-racy index entries, as after a real pause: within the
    /// same second git re-reads content, which hides refresh bugs.
    pub fn settle(&self) {
        let past = SystemTime::now() - Duration::from_secs(60);
        for rel in [A, B] {
            let f = fs::File::options()
                .write(true)
                .open(self.root.join(rel))
                .unwrap();
            f.set_modified(past).unwrap();
        }
        self.git_ok(&["update-index", "--refresh"]);
    }

    pub fn add_unsigned_recipient(&self, ring: &str) {
        let stranger = age::x25519::Identity::generate().to_public().to_string();
        let toml = fs::read_to_string(self.root.join("git-agecrypt.toml")).unwrap();
        let toml = toml.replace(
            &format!("\"{ring}\" = [\""),
            &format!("\"{ring}\" = [\"{stranger}\", \""),
        );
        self.write("git-agecrypt.toml", &toml);
    }

    pub fn cache_dir(&self) -> PathBuf {
        let gitdir = self.git_ok(&["rev-parse", "--absolute-git-dir"]);
        PathBuf::from(gitdir.trim()).join("git-agecrypt")
    }
}
