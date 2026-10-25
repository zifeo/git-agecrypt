// SPDX-License-Identifier: MPL-2.0

//! The policy is one file, git-agecrypt.toml: key names, [policy], and a
//! closing [signature]. These pin its format and the refusals around it.

// sh identityCommands, ssh-keygen signers and includeIf on POSIX paths.
#![cfg(unix)]

mod common;

use std::{fs, path::Path};

use common::*;

/// A throwaway post-quantum recipient (public half only), to mix with classic keys.
const PQ: &str = "age1pq18kz5tt9pxljm0nywy2qst6jnr5cy7l45ph0vrv5cxakjymx050j4w5p8c9upkrf3kp0ranypywpma5gu5zwnjk6fsedrukpddd5fjsw8v4tu200guumgg4v99at2ewyypdhtz86yvdsry2jlzaf69al6ny20vsuavp2r09sjj9ypsldv4xtrk08zg7q5v2ewlsvsywp2d992gr83zq7cacyj9f4nnkppqy8qysvgqmr4t6nnqcpp2z6xw3c7xcc6dz97pw9vw3c5d8nk4hayjqsftsmzw27pardh6nxtqhqxtxenz4fzhcykgd98gwz829v3qy2cz97mkq3xx0uvt62j4u9n0pwsq7ja5gzlx8mmfrcxtyrkjhemm38jr93dfyum0pxrtucjqqykwflxvlq2yemrav5qyrep437dvv980stzt0k9atx4q09vwjlj56hh0q4gsuzqwef33gq9jw3cl33ln4djr0vhsn0me6tnjzuvjchxtwa5hljzgldzh0rjscnr83c0usr8xxs4rudu3xezj2gezmyqeejyttur9temsrzl9yxl55h027stypynwlgrrgszje5sze3hgvfk3rcm9casvr6q2j3e6eglrsfq69s933f3990a4d9yk6ycuaezwl6us24npguujnjncpt6rkya50tmvx7qflc89puecak853mak66j5sext3cxkuyxr9898pd3n4sce5jurlqsnyc0ryz96s5538etv3e9ylexpt8lxcre0k2c5yu2muvpsvp24s7yqg5ghvv4t65twrsgqnyzs8angz7kma2cd6fmw0jf4csq2yv75tqvqeg4qaeye3x4d6zkknvyt08xwxukhpf9twu5pjyk8wupusaudft3y5q3lclgtkmdhxxa7au56astpcz6hsgcp2pttvf6vfecpznw3kd23v5nfp2swkpz5vttfq9vx63ve4l6sv6hqxfte0p8eq3llsupvda5w065djmmhywn6qx0q5tntnquqzqu82v8g7e8tuvdfjfxm2rzke3updg2xdreq547skemmeexkg428thcgvhzhx32k8kzxlqx2grj2eaxs9cr4d54r2q40l22gaxff3vtqj74kvxrw3quc2yfqv78ycgvwfkjshxrpxdn9ly9yexyhwjgmww9fxxt8ax95p6nwg39qvfhzww54j6qcp7pckjy3993r887dsk8ykdxug38z38r8tcc0quhtz524c9gm3v6trn98drly5zqp2zk29mc7zc8rul63jw956pxjp0tkgsyxajugqsugc2l8qnw49hhm7u7kv4x4au3qzlfqnykzqydrrq9dy2ht3d82ytjkxmcgekq45gg677yrk2qe930yrqzs7aha9k90u32zg84w5wfjxaffj8qhdyrhvz26scj9wqfw22xspc502aaaq3h9ujxhzd940me5u944nzf0vn260u64s90k7asquuy4x6hz2d4uxp3p2ulv7jtk9sdy2js4mpeta9mgd57gn44u7g6g7jdk59y8arjx93tc9umw74x7ejrzgtfd7wucpw9qx0exxam2jacs4ekm5umk470vzqkq6xr844nkeec3uq2wrct2hqzv96twuut3z6kewz4hrj7jkqpcfupryelpnruw7mu99lzx3vfq7mk7q3a99n5lrlp3z4tkmc4lqwrcc6e8p2nkvgg5vhj55dnlsdp234pqly6eefqk2epxm40y0zy5kd2vqv2f5nkhx8yx0vdxy0dgaj5fhf9f2s38wcy90uhjcg6fde4t35k6sfh2zkz5murjskdr5eq90akx8egw954xrcy5alwh0ksxu9px0ajw0l62g6ne28y2zgeffa5whyq8w2vk4dnccgntl63wdx8vw94g69fjg03ul02kyqanxdfxpgtu0gehqqj5t3kgpj7pchq00ar";

fn toml(r: &Repo) -> String {
    fs::read_to_string(r.root.join("git-agecrypt.toml")).unwrap()
}

fn public(key_file: &Path) -> String {
    let id: age::x25519::Identity = fs::read_to_string(key_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    id.to_public().to_string()
}

fn verify(r: &Repo) -> std::process::Output {
    r.ac(&["verify", "--trust", r.trust().to_str().unwrap()])
}

#[test]
fn the_policy_is_one_file_signed_last() {
    let r = Repo::new();
    let t = toml(&r);
    assert!(t.contains("[policy]"), "{t}");
    assert!(
        t.contains("[signature]\nssh = \"\"\"\n-----BEGIN SSH SIGNATURE-----"),
        "{t}"
    );
    assert!(t.ends_with("-----END SSH SIGNATURE-----\n\"\"\"\n"), "{t}");
    assert!(!r.root.join("git-agecrypt.version").exists());
    assert!(!r.root.join("git-agecrypt.toml.sig").exists());
    let out = ok(verify(&r), "verify");
    assert!(out.contains("policy v1 signed by owner@test"), "{out}");
}

#[test]
fn an_edit_above_the_signature_voids_it() {
    let r = Repo::new();
    r.add_unsigned_recipient("ring-b/**");
    let out = verify(&r);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does not match"), "{}", stderr(&out));
}

#[test]
fn an_unknown_key_name_is_refused_at_sign() {
    let r = Repo::new();
    let b = public(&r.outside("b.key"));
    r.write("git-agecrypt.toml", &toml(&r).replace(&b, "nobody"));
    let out = r.ac(&["sign"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unknown key name 'nobody'"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_ring_mixing_classic_and_post_quantum_keys_is_refused_at_sign() {
    let r = Repo::new();
    let a = public(&r.outside("a.key"));
    r.write(
        "git-agecrypt.toml",
        &toml(&r).replace(&a, &format!("{a}\", \"{PQ}")),
    );
    let out = r.ac(&["sign"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("mixes age1pq1 and classic"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_key_name_spelled_like_a_recipient_is_refused() {
    let r = Repo::new();
    let (a, b) = (public(&r.outside("a.key")), public(&r.outside("b.key")));
    let hijack = format!("[keys]\n\"{a}\" = \"{b}\"\n\n[config]");
    r.write(
        "git-agecrypt.toml",
        &toml(&r).replacen("[config]", &hijack, 1),
    );
    let out = r.ac(&["sign"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a recipient"), "{}", stderr(&out));
}
