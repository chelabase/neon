//! F3 coder's edge cases beyond the RED set: pg_ident files from before the
//! markers, cut ident blocks, a block at the very end of a file, and certificate
//! chains through an intermediate.

use std::path::{Path, PathBuf};

use compute_api::responses::TlsConfig;
use compute_api::spec::MemberLogins;
use compute_tools::spec::{member_hba_block, realtime_hba_block, update_pg_hba, update_pg_ident};
use compute_tools::tls::{reload_tls_files, verify_cert_chains_to_ca};

const IDENT_HEAD: &str = "# chelabase: member certificate map (chelabase_member)\n";
const IDENT_TAIL: &str = "# chelabase: end of member certificate map\n";
const RT_IDENT: &str = "# chelabase: realtime certificate map (chelabase_realtime)\n\
# chelabase: end of realtime certificate map\n";

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("PG_VERSION"), "17\n").unwrap();
    dir
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// A pg_ident.conf written before the markers: its unmarked member lines go
/// (a dropped CN must stop mapping), the block goes first, the rest stays.
#[test]
fn unmarked_member_ident_lines_are_replaced_by_the_block() {
    let dir = fresh("f3e_ident_legacy");
    let ident = dir.join("pg_ident.conf");
    std::fs::write(
        &ident,
        "mymap\tbob\tbob\nchelabase_member\tcn-old\t/^cb_m_[0-9a-f]{32}$\n# tail comment\n",
    )
    .unwrap();
    update_pg_ident(&dir, None, Some(&logins(&[], &["cn-new"])), None).unwrap();
    // K4 (W31): the realtime map block (no CN without realtime_logins) goes right
    // after the member one.
    assert_eq!(
        read(&ident),
        format!(
            "{IDENT_HEAD}chelabase_member\tcn-new\t/^cb_m_[0-9a-f]{{32}}$\n{IDENT_TAIL}\
{RT_IDENT}mymap\tbob\tbob\n# tail comment\n"
        )
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A cut ident block is an error naming the file, which is left as it was.
#[test]
fn a_cut_ident_block_is_refused() {
    for (i, text) in [
        format!("{IDENT_HEAD}mymap\tbob\tbob\n"),
        format!("mymap\tbob\tbob\n{IDENT_TAIL}"),
        format!("{IDENT_TAIL}{IDENT_HEAD}"),
        format!("{IDENT_HEAD}{IDENT_HEAD}{IDENT_TAIL}"),
    ]
    .iter()
    .enumerate()
    {
        let dir = fresh(&format!("f3e_ident_cut_{i}"));
        let ident = dir.join("pg_ident.conf");
        std::fs::write(&ident, text).unwrap();
        let err = update_pg_ident(&dir, None, Some(&logins(&[], &["cn-a"])), None).unwrap_err();
        assert!(format!("{err:#}").contains("pg_ident.conf"), "{err:#}");
        assert_eq!(&read(&ident), text);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The end marker as the file's last line, without a newline, is still the
/// block's end; Windows line ends on the markers are read as markers too.
#[test]
fn a_block_at_the_end_of_the_file_is_replaced() {
    let old = logins(&["10.213.4.10/32"], &["cn"]);
    let new = logins(&["10.213.4.11/32"], &["cn"]);
    let md5 = "host\tall\t\tall\t\tall\t\tmd5\n";

    let dir = fresh("f3e_hba_end");
    let hba = dir.join("pg_hba.conf");
    let block = member_hba_block(Some(&old), true).unwrap();
    std::fs::write(&hba, format!("{md5}{}", block.trim_end_matches('\n'))).unwrap();
    update_pg_hba(&dir, None, Some(&new), None, true).unwrap();
    // K4 (W31): the realtime block goes right after the member block.
    assert_eq!(
        read(&hba),
        format!(
            "{md5}{}{}",
            member_hba_block(Some(&new), true).unwrap(),
            realtime_hba_block(None, true).unwrap()
        )
    );
    std::fs::remove_dir_all(&dir).unwrap();

    let dir = fresh("f3e_hba_crlf");
    let hba = dir.join("pg_hba.conf");
    std::fs::write(&hba, format!("{}{md5}", block.replace('\n', "\r\n"))).unwrap();
    update_pg_hba(&dir, None, Some(&new), None, true).unwrap();
    assert_eq!(
        read(&hba),
        format!(
            "{}{}{md5}",
            member_hba_block(Some(&new), true).unwrap(),
            realtime_hba_block(None, true).unwrap()
        )
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn make_ca(dir: &Path, name: &str, cn: &str) {
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.crt"),
            "-days",
            "2",
            "-subj",
            &format!("/CN={cn}"),
        ],
    );
}

fn sign(dir: &Path, name: &str, cn: &str, issuer: &str) {
    openssl(
        dir,
        &[
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            &format!("/CN={cn}"),
        ],
    );
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{issuer}.crt"),
            "-CAkey",
            &format!("{issuer}.key"),
            "-CAcreateserial",
            "-days",
            "2",
            "-out",
            &format!("{name}.crt"),
        ],
    );
}

/// A server certificate file carrying its intermediate chains to the root in
/// the CA file; another root, an empty CA file or a leaf without its
/// intermediate doesn't.
#[test]
fn a_chain_through_an_intermediate_is_followed() {
    let dir = fresh("f3e_chain");
    make_ca(&dir, "root", "root");
    make_ca(&dir, "other", "root");
    sign(&dir, "inter", "inter", "root");
    sign(&dir, "leaf", "compute", "inter");
    let root = read(&dir.join("root.crt"));
    let other = read(&dir.join("other.crt"));
    let leaf = read(&dir.join("leaf.crt"));
    let chain = format!("{leaf}{}", read(&dir.join("inter.crt")));

    verify_cert_chains_to_ca(&chain, &root).unwrap();
    assert!(
        verify_cert_chains_to_ca(&chain, &other).is_err(),
        "another root"
    );
    assert!(
        verify_cert_chains_to_ca(&chain, "").is_err(),
        "empty CA file"
    );
    assert!(
        verify_cert_chains_to_ca(&leaf, &root).is_err(),
        "no intermediate"
    );
    verify_cert_chains_to_ca(&leaf, &read(&dir.join("inter.crt"))).unwrap();

    // Through reload_tls_files: the chain file is copied as is.
    std::fs::create_dir_all(dir.join("pgdata")).unwrap();
    std::fs::copy(dir.join("leaf.key"), dir.join("server.key")).unwrap();
    std::fs::write(dir.join("server.crt"), &chain).unwrap();
    let tls = TlsConfig {
        key_path: dir.join("server.key").to_string_lossy().into(),
        cert_path: dir.join("server.crt").to_string_lossy().into(),
        ca_path: Some(dir.join("root.crt").to_string_lossy().into()),
    };
    reload_tls_files(&dir.join("pgdata"), &tls, || Ok(())).unwrap();
    assert_eq!(read(&dir.join("pgdata/server.crt")), chain);
    std::fs::remove_dir_all(&dir).unwrap();
}
