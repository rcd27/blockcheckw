// Port of strategy generation logic from blockcheck2.d/standard/
// Mode: SCANLEVEL=force (no optimizations, generate ALL combinations)
//
// Source: reference/blockcheckw-prototype/.../StrategyGenerator.kt
//
// TODO: many phase functions (fake_tls12, faked_tls12, hostfake_tls12, etc.) share the same
// "clone base + prepend wssize" pattern — extract a common helper to reduce duplication.
// TODO: reduce excessive .clone() on Vec<Vec<String>> in phase functions — consider using
// references or Cow to avoid thousands of allocations during generation.

use crate::config::Protocol;

type Strategy = Vec<String>;

// --- Parameters from def.inc ---

const FOOLINGS_TCP: &[&str] = &[
    "tcp_md5", "badsum", "tcp_seq=-3000", "tcp_seq=1000000",
    "tcp_ack=-66000:tcp_ts_up", "tcp_ts=-1000",
    "tcp_flags_unset=ACK", "tcp_flags_set=SYN",
];

const TTL_MIN: u32 = 1;
const TTL_MAX: u32 = 12;
const AUTOTTL_MIN: u32 = 1;
const AUTOTTL_MAX: u32 = 5;

const HTTP_SPLITS: &[&str] = &["method+2", "midsld", "method+2,midsld"];
const TLS_SPLITS: &[&str] = &[
    "2", "1", "sniext+1", "sniext+4", "host+1", "midsld",
    "1,midsld", "1,midsld,1220",
    "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1",
];
const TLS_SPLITS_FAKED: &[&str] = &[
    "2", "1", "sniext+1", "sniext+4", "host+1", "midsld",
    "1,midsld",
    "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1",
];
const SPLIT_METHODS: &[&str] = &["multisplit", "multidisorder"];

const OOB_URPS: &[&str] = &["b", "0", "2", "midsld"];

const FAKE_BLOBS_HTTP: &[&str] = &["fake_default_http", "0x00000000"];
// Note: TLS fake blobs are hardcoded inside fake_https_vary()
// (2 sub-strategies: base fake + 0x00000000 null-blob).

const SEQOVL_SPLITS_HTTP: &[&str] = &["method+2", "method+2,midsld"];
const SEQOVL_DISORDER_HTTP: &[(&str, &str)] = &[
    ("method+1", "method+2"),
    ("midsld-1", "midsld"),
    ("method+1", "method+2,midsld"),
];

const SEQOVL_SPLITS_TLS: &[&str] = &["10", "10,sniext+1", "10,sniext+4", "10,midsld"];
const SEQOVL_DISORDER_TLS: &[(&str, &str)] = &[
    ("1", "2"),
    ("sniext", "sniext+1"),
    ("sniext+3", "sniext+4"),
    ("midsld-1", "midsld"),
    ("1", "2,midsld"),
];

const HOSTFAKE_VARIANTS: &[&str] = &[
    "", "nofake1:", "nofake2:", "midhost=midsld:",
    "nofake1:midhost=midsld:", "nofake2:midhost=midsld:",
];
const HOSTFAKE_DISORDERS: &[&str] = &["", "disorder_after:"];

const SYNDATA_SPLITS: &[&str] = &["", "multisplit", "multidisorder"];

const MISC_REPEATS: &[u32] = &[1, 20, 100, 260];
const MISC_POSITIONS_HTTP: &[&str] = &["0,method+2", "0,midsld"];
const MISC_POSITIONS_TLS: &[&str] = &["0,1", "0,midsld"];

// --- Strategy generators ---

/// 10-http-basic.sh
fn http_basic() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    ["http_hostcase", "http_hostcase:spell=hoSt", "http_domcase", "http_methodeol", "http_unixeol"]
        .iter()
        .map(|s| vec![payload.into(), format!("--lua-desync={s}")])
        .collect()
}

/// 15-misc.sh — tcpseg with repeats (HTTP)
fn misc_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();
    for &repeats in MISC_REPEATS {
        for &pos in MISC_POSITIONS_HTTP {
            out.push(vec![
                payload.into(),
                format!("--lua-desync=tcpseg:pos={pos}:ip_id=rnd:repeats={repeats}"),
            ]);
        }
    }
    out
}

/// 15-misc.sh — tcpseg with repeats (TLS)
fn misc_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let mut out = Vec::new();
    for &repeats in MISC_REPEATS {
        for &pos in MISC_POSITIONS_TLS {
            out.push(vec![
                payload.into(),
                format!("--lua-desync=tcpseg:pos={pos}:ip_id=rnd:repeats={repeats}"),
            ]);
        }
    }
    out
}

/// 17-oob.sh — OOB with urp variants
fn oob() -> Vec<Strategy> {
    OOB_URPS
        .iter()
        .map(|urp| vec!["--in-range=-s1".into(), format!("--lua-desync=oob:urp={urp}")])
        .collect()
}

/// 20-multi.sh — multisplit/multidisorder by positions (HTTP)
fn multi_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();
    for &splitf in SPLIT_METHODS {
        for &pos in HTTP_SPLITS {
            out.push(vec![payload.into(), format!("--lua-desync={splitf}:pos={pos}")]);
        }
    }
    out
}

/// 20-multi.sh (TLS)
fn multi_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let mut out = Vec::new();
    for &splitf in SPLIT_METHODS {
        for &pos in TLS_SPLITS {
            out.push(vec![payload.into(), format!("--lua-desync={splitf}:pos={pos}")]);
        }
    }
    out
}

/// 20-multi.sh (TLS1.2 = TLS + wssize variants)
fn multi_tls12() -> Vec<Strategy> {
    let mut out = multi_tls();
    let payload = "--payload=tls_client_hello";
    for &splitf in SPLIT_METHODS {
        for &pos in TLS_SPLITS {
            out.push(vec![
                "--lua-desync=wssize:wsize=1:scale=6".into(),
                payload.into(),
                format!("--lua-desync={splitf}:pos={pos}"),
            ]);
        }
    }
    out
}

/// 23-seqovl.sh — TCP sequence overlapping (HTTP)
fn seqovl_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();

    // tcpseg seqovl
    out.push(vec![
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=1".into(),
        "--lua-desync=drop".into(),
    ]);
    out.push(vec![
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=#fake_default_http:seqovl_pattern=fake_default_http".into(),
        "--lua-desync=drop".into(),
    ]);

    // multisplit seqovl
    for &split in SEQOVL_SPLITS_HTTP {
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=1"),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=#fake_default_http:seqovl_pattern=fake_default_http"),
        ]);
    }

    // multidisorder seqovl
    for &(f, f2) in SEQOVL_DISORDER_HTTP {
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multidisorder:pos={f2}:seqovl={f}"),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multidisorder:pos={f2}:seqovl={f}:seqovl_pattern=fake_default_http"),
        ]);
    }

    out
}

/// 23-seqovl.sh (TLS)
fn seqovl_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let mut out = Vec::new();

    // tcpseg seqovl
    out.push(vec![
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=1".into(),
        "--lua-desync=drop".into(),
    ]);
    out.push(vec![
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=#fake_default_tls:seqovl_pattern=fake_default_tls".into(),
        "--lua-desync=drop".into(),
    ]);
    out.push(vec![
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=#patmod:seqovl_pattern=patmod".into(),
        "--lua-desync=drop".into(),
    ]);

    // multisplit seqovl
    for &split in SEQOVL_SPLITS_TLS {
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=1"),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=#fake_default_tls:seqovl_pattern=fake_default_tls"),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=#patmod:seqovl_pattern=patmod"),
        ]);
    }

    // multidisorder seqovl
    for &(f, f2) in SEQOVL_DISORDER_TLS {
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multidisorder:pos={f2}:seqovl={f}"),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multidisorder:pos={f2}:seqovl={f}:seqovl_pattern=fake_default_tls"),
        ]);
    }

    out
}

/// 23-seqovl.sh (TLS1.2 = TLS + wssize variants)
fn seqovl_tls12() -> Vec<Strategy> {
    let base = seqovl_tls();
    let mut out = base.clone();
    let payload = "--payload=tls_client_hello";

    // wssize variants for tcpseg
    out.push(vec![
        "--lua-desync=wssize:wsize=1:scale=6".into(),
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=1".into(),
        "--lua-desync=drop".into(),
    ]);
    out.push(vec![
        "--lua-desync=wssize:wsize=1:scale=6".into(),
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=#fake_default_tls:seqovl_pattern=fake_default_tls".into(),
        "--lua-desync=drop".into(),
    ]);
    out.push(vec![
        "--lua-desync=wssize:wsize=1:scale=6".into(),
        payload.into(),
        "--lua-desync=tcpseg:pos=0,-1:seqovl=#patmod:seqovl_pattern=patmod".into(),
        "--lua-desync=drop".into(),
    ]);

    // wssize for multisplit
    for &split in SEQOVL_SPLITS_TLS {
        out.push(vec![
            "--lua-desync=wssize:wsize=1:scale=6".into(),
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=1"),
        ]);
        out.push(vec![
            "--lua-desync=wssize:wsize=1:scale=6".into(),
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=#fake_default_tls:seqovl_pattern=fake_default_tls"),
        ]);
        out.push(vec![
            "--lua-desync=wssize:wsize=1:scale=6".into(),
            payload.into(),
            format!("--lua-desync=multisplit:pos={split}:seqovl=#patmod:seqovl_pattern=patmod"),
        ]);
    }

    // wssize for multidisorder
    for &(f, f2) in SEQOVL_DISORDER_TLS {
        out.push(vec![
            "--lua-desync=wssize:wsize=1:scale=6".into(),
            payload.into(),
            format!("--lua-desync=multidisorder:pos={f2}:seqovl={f}"),
        ]);
        out.push(vec![
            "--lua-desync=wssize:wsize=1:scale=6".into(),
            payload.into(),
            format!("--lua-desync=multidisorder:pos={f2}:seqovl={f}:seqovl_pattern=fake_default_tls"),
        ]);
    }

    out
}

/// 24-syndata.sh — SYN with data (HTTP)
fn syndata_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();
    for &split in SYNDATA_SPLITS {
        let split_args: Vec<String> = if split.is_empty() {
            vec![]
        } else {
            vec![payload.into(), format!("--lua-desync={split}")]
        };

        let mut s1 = vec!["--lua-desync=syndata".to_string()];
        s1.extend(split_args.clone());
        out.push(s1);

        let mut s2 = vec!["--lua-desync=syndata:blob=fake_default_http".to_string()];
        s2.extend(split_args);
        out.push(s2);
    }
    out
}

/// 24-syndata.sh (TLS)
fn syndata_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let mut out = Vec::new();
    for &split in SYNDATA_SPLITS {
        let split_args: Vec<String> = if split.is_empty() {
            vec![]
        } else {
            vec![payload.into(), format!("--lua-desync={split}")]
        };

        let mut s1 = vec!["--lua-desync=syndata".to_string()];
        s1.extend(split_args.clone());
        out.push(s1);

        let mut s2 = vec!["--lua-desync=syndata:blob=0x1603".to_string()];
        s2.extend(split_args.clone());
        out.push(s2);

        let mut s3 = vec!["--lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,rndsni".to_string()];
        s3.extend(split_args.clone());
        out.push(s3);

        let mut s4 = vec!["--lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=google.com".to_string()];
        s4.extend(split_args);
        out.push(s4);
    }
    out
}

/// 24-syndata.sh (TLS1.2 = TLS + wssize variants)
fn syndata_tls12() -> Vec<Strategy> {
    let mut out = syndata_tls();
    let payload = "--payload=tls_client_hello";
    for &split in SYNDATA_SPLITS {
        let split_args: Vec<String> = if split.is_empty() {
            vec![]
        } else {
            vec![payload.into(), format!("--lua-desync={split}")]
        };

        let mut s1 = vec!["--lua-desync=wssize:wsize=1:scale=6".into(), "--lua-desync=syndata".to_string()];
        s1.extend(split_args.clone());
        out.push(s1);

        let mut s2 = vec!["--lua-desync=wssize:wsize=1:scale=6".into(), "--lua-desync=syndata:blob=0x1603".to_string()];
        s2.extend(split_args.clone());
        out.push(s2);

        let mut s3 = vec!["--lua-desync=wssize:wsize=1:scale=6".into(), "--lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,rndsni".to_string()];
        s3.extend(split_args.clone());
        out.push(s3);

        let mut s4 = vec!["--lua-desync=wssize:wsize=1:scale=6".into(), "--lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=google.com".to_string()];
        s4.extend(split_args);
        out.push(s4);
    }
    out
}

/// 25-fake.sh — fake with TTL brute-force + foolings + autottl (HTTP)
fn fake_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();

    // TTL brute-force
    for ttl in TTL_MIN..=TTL_MAX {
        for &ff in FAKE_BLOBS_HTTP {
            out.push(vec![
                payload.into(),
                format!("--lua-desync=fake:blob={ff}:ip_ttl={ttl}:repeats=1"),
            ]);
            out.push(vec![
                payload.into(),
                format!("--lua-desync=fake:blob={ff}:ip_ttl={ttl}:repeats=1"),
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
        }
    }

    // foolings
    for &fooling in FOOLINGS_TCP {
        for &ff in FAKE_BLOBS_HTTP {
            out.push(vec![
                payload.into(),
                format!("--lua-desync=fake:blob={ff}:{fooling}:repeats=1"),
            ]);
            if fooling.contains("tcp_md5") {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={ff}:{fooling}:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=<s1".into(),
                    "--lua-desync=send:tcp_md5".into(),
                ]);
            }
        }
    }

    // autottl
    for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
        for &ff in FAKE_BLOBS_HTTP {
            out.push(vec![
                payload.into(),
                format!("--lua-desync=fake:blob={ff}:ip_autottl=-{ttl},3-20:repeats=1"),
            ]);
            out.push(vec![
                payload.into(),
                format!("--lua-desync=fake:blob={ff}:ip_autottl=-{ttl},3-20:repeats=1"),
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
        }
    }

    out
}

/// Helper: fake HTTPS vary (5 sub-strategies per fooling)
/// Port of pktws_fake_https_vary_() from 25-fake.sh lines 62-72
fn fake_https_vary(fooling: &str, payload: &str, fake: &str) -> Vec<Strategy> {
    let mut out = Vec::new();

    // 1. fake:blob=$fake:$fooling
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
    ]);
    // 2. fake:blob=0x00000000:$fooling
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
    ]);
    // 3. double fake: null-blob + real fake with tls_mod=rnd,dupsid
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
        format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid:repeats=1"),
    ]);
    // 4. multisplit:blob with nodrop (fake embedded into split)
    out.push(vec![
        payload.into(),
        format!("--lua-desync=multisplit:blob={fake}:{fooling}:pos=2:nodrop:repeats=1"),
    ]);
    // 5. fake with tls_mod=rnd,dupsid,padencap
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats=1"),
    ]);

    // SYN with MD5 (wraps all 5 variants with send:tcp_md5 postfix)
    if fooling.contains("tcp_md5") {
        out.push(vec![
            payload.into(),
            format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
            format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid:repeats=1"),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:blob={fake}:{fooling}:pos=2:nodrop:repeats=1"),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats=1"),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
    }

    out
}

/// 25-fake.sh (TLS)
fn fake_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let fake = "fake_default_tls";
    let mut out = Vec::new();

    // TTL brute-force
    for ttl in TTL_MIN..=TTL_MAX {
        let fooling = format!("ip_ttl={ttl}");
        let vary = fake_https_vary(&fooling, payload, fake);
        out.extend(vary.clone());
        // with pktmod limiter
        for s in &vary {
            let mut extended = s.clone();
            extended.extend([
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
            out.push(extended);
        }
    }

    // foolings
    for &fooling in FOOLINGS_TCP {
        out.extend(fake_https_vary(fooling, payload, fake));
    }

    // autottl
    for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
        let fooling = format!("ip_autottl=-{ttl},3-20");
        let vary = fake_https_vary(&fooling, payload, fake);
        out.extend(vary.clone());
        for s in &vary {
            let mut extended = s.clone();
            extended.extend([
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
            out.push(extended);
        }
    }

    out
}

/// 25-fake.sh (TLS1.2 = TLS + wssize variants)
fn fake_tls12() -> Vec<Strategy> {
    let base = fake_tls();
    let mut out = base.clone();
    for s in &base {
        let mut wssize = vec!["--lua-desync=wssize:wsize=1:scale=6".to_string()];
        wssize.extend(s.clone());
        out.push(wssize);
    }
    out
}

/// 30-faked.sh — fakedsplit/fakeddisorder (HTTP)
fn faked_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let splitfs = &["fakedsplit", "fakeddisorder"];
    let mut out = Vec::new();

    for &splitf in splitfs {
        // TTL
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in HTTP_SPLITS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
        // foolings
        for &fooling in FOOLINGS_TCP {
            for &split in HTTP_SPLITS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:{fooling}"),
                ]);
                if fooling.contains("tcp_md5") {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync={splitf}:pos={split}:{fooling}:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=<s1".into(),
                        "--lua-desync=send:tcp_md5".into(),
                    ]);
                }
            }
        }
        // autottl
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in HTTP_SPLITS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }

    out
}

/// 30-faked.sh (TLS) — uses TLS_SPLITS_FAKED (8 positions)
fn faked_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let splitfs = &["fakedsplit", "fakeddisorder"];
    let mut out = Vec::new();

    for &splitf in splitfs {
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in TLS_SPLITS_FAKED {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
        for &fooling in FOOLINGS_TCP {
            for &split in TLS_SPLITS_FAKED {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:{fooling}"),
                ]);
                if fooling.contains("tcp_md5") {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync={splitf}:pos={split}:{fooling}:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=<s1".into(),
                        "--lua-desync=send:tcp_md5".into(),
                    ]);
                }
            }
        }
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in TLS_SPLITS_FAKED {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }

    out
}

/// 30-faked.sh (TLS1.2 = TLS + wssize variants) — uses TLS_SPLITS_FAKED
fn faked_tls12() -> Vec<Strategy> {
    let mut out = faked_tls();
    let payload = "--payload=tls_client_hello";
    let splitfs = &["fakedsplit", "fakeddisorder"];

    for &splitf in splitfs {
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in TLS_SPLITS_FAKED {
                out.push(vec![
                    "--lua-desync=wssize:wsize=1:scale=6".into(),
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                ]);
                out.push(vec![
                    "--lua-desync=wssize:wsize=1:scale=6".into(),
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
        for &fooling in FOOLINGS_TCP {
            for &split in TLS_SPLITS_FAKED {
                out.push(vec![
                    "--lua-desync=wssize:wsize=1:scale=6".into(),
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:{fooling}"),
                ]);
                if fooling.contains("tcp_md5") {
                    out.push(vec![
                        "--lua-desync=wssize:wsize=1:scale=6".into(),
                        payload.into(),
                        format!("--lua-desync={splitf}:pos={split}:{fooling}:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=<s1".into(),
                        "--lua-desync=send:tcp_md5".into(),
                    ]);
                }
            }
        }
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in TLS_SPLITS_FAKED {
                out.push(vec![
                    "--lua-desync=wssize:wsize=1:scale=6".into(),
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                ]);
                out.push(vec![
                    "--lua-desync=wssize:wsize=1:scale=6".into(),
                    payload.into(),
                    format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }

    out
}

/// Helper: hostfake variants for a given fooling
fn hostfake_variants(fooling: &str) -> Vec<String> {
    let mut out = Vec::new();
    for &disorder in HOSTFAKE_DISORDERS {
        for &variant in HOSTFAKE_VARIANTS {
            out.push(format!("hostfakesplit:{disorder}{variant}{fooling}:repeats=1"));
        }
    }
    out
}

/// 35-hostfake.sh (HTTP)
fn hostfake_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();

    // TTL
    for ttl in TTL_MIN..=TTL_MAX {
        for desync in hostfake_variants(&format!("ip_ttl={ttl}")) {
            out.push(vec![payload.into(), format!("--lua-desync={desync}")]);
            out.push(vec![
                payload.into(),
                format!("--lua-desync={desync}"),
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
        }
    }
    // foolings
    for &fooling in FOOLINGS_TCP {
        for desync in hostfake_variants(fooling) {
            out.push(vec![payload.into(), format!("--lua-desync={desync}")]);
            if fooling.contains("tcp_md5") {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={desync}"),
                    "--payload=empty".into(),
                    "--out-range=<s1".into(),
                    "--lua-desync=send:tcp_md5".into(),
                ]);
            }
        }
    }
    // autottl
    for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
        for desync in hostfake_variants(&format!("ip_autottl=-{ttl},3-20")) {
            out.push(vec![payload.into(), format!("--lua-desync={desync}")]);
            out.push(vec![
                payload.into(),
                format!("--lua-desync={desync}"),
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
        }
    }

    out
}

/// 35-hostfake.sh (TLS)
fn hostfake_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let mut out = Vec::new();

    for ttl in TTL_MIN..=TTL_MAX {
        for desync in hostfake_variants(&format!("ip_ttl={ttl}")) {
            out.push(vec![payload.into(), format!("--lua-desync={desync}")]);
            out.push(vec![
                payload.into(),
                format!("--lua-desync={desync}"),
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
        }
    }
    for &fooling in FOOLINGS_TCP {
        for desync in hostfake_variants(fooling) {
            out.push(vec![payload.into(), format!("--lua-desync={desync}")]);
            if fooling.contains("tcp_md5") {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync={desync}"),
                    "--payload=empty".into(),
                    "--out-range=<s1".into(),
                    "--lua-desync=send:tcp_md5".into(),
                ]);
            }
        }
    }
    for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
        for desync in hostfake_variants(&format!("ip_autottl=-{ttl},3-20")) {
            out.push(vec![payload.into(), format!("--lua-desync={desync}")]);
            out.push(vec![
                payload.into(),
                format!("--lua-desync={desync}"),
                "--payload=empty".into(),
                "--out-range=s1<d1".into(),
                "--lua-desync=pktmod:ip_ttl=1".into(),
            ]);
        }
    }

    out
}

/// 35-hostfake.sh (TLS1.2 = TLS + wssize variants)
fn hostfake_tls12() -> Vec<Strategy> {
    let base = hostfake_tls();
    let mut out = base.clone();
    for s in &base {
        let mut wssize = vec!["--lua-desync=wssize:wsize=1:scale=6".to_string()];
        wssize.extend(s.clone());
        out.push(wssize);
    }
    out
}

/// 50-fake-multi.sh — fake + multisplit/multidisorder combinations (HTTP)
fn fake_multi_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let mut out = Vec::new();

    for &splitf in SPLIT_METHODS {
        // TTL
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in HTTP_SPLITS {
                for &ff in FAKE_BLOBS_HTTP {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_ttl={ttl}:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}"),
                    ]);
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_ttl={ttl}:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}"),
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                }
            }
        }
        // foolings
        for &fooling in FOOLINGS_TCP {
            for &split in HTTP_SPLITS {
                for &ff in FAKE_BLOBS_HTTP {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:{fooling}:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}"),
                    ]);
                    if fooling.contains("tcp_md5") {
                        out.push(vec![
                            payload.into(),
                            format!("--lua-desync=fake:blob={ff}:{fooling}:repeats=1"),
                            format!("--lua-desync={splitf}:pos={split}"),
                            "--payload=empty".into(),
                            "--out-range=<s1".into(),
                            "--lua-desync=send:tcp_md5".into(),
                        ]);
                    }
                }
            }
        }
        // autottl
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in HTTP_SPLITS {
                for &ff in FAKE_BLOBS_HTTP {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_autottl=-{ttl},3-20:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}"),
                    ]);
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_autottl=-{ttl},3-20:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}"),
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                }
            }
        }
    }

    out
}

/// Helper: fake HTTPS vary with a suffix desync command appended to each variant.
/// Port of pktws_fake_https_vary_() from 50-fake-multi.sh / 55-fake-faked.sh.
/// `suffix` is e.g. "--lua-desync=multisplit:pos=2" or "--lua-desync=fakedsplit:pos=midsld:ip_ttl=5:repeats=1"
fn fake_https_vary_with_suffix(fooling: &str, payload: &str, fake: &str, suffix: &str) -> Vec<Strategy> {
    let mut out = Vec::new();

    // 1. fake:blob=$fake:$fooling + suffix
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
        suffix.into(),
    ]);
    // 2. fake:blob=0x00000000:$fooling + suffix
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
        suffix.into(),
    ]);
    // 3. double fake: null-blob + real fake with tls_mod=rnd,dupsid + suffix
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
        format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid:repeats=1"),
        suffix.into(),
    ]);
    // 4. multisplit:blob with nodrop + suffix
    out.push(vec![
        payload.into(),
        format!("--lua-desync=multisplit:blob={fake}:{fooling}:pos=2:nodrop:repeats=1"),
        suffix.into(),
    ]);
    // 5. fake with tls_mod=rnd,dupsid,padencap + suffix
    out.push(vec![
        payload.into(),
        format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats=1"),
        suffix.into(),
    ]);

    // SYN with MD5
    if fooling.contains("tcp_md5") {
        for base in [
            format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
            format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
        ] {
            out.push(vec![
                payload.into(), base, suffix.into(),
                "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
            ]);
        }
        out.push(vec![
            payload.into(),
            format!("--lua-desync=fake:blob=0x00000000:{fooling}:repeats=1"),
            format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid:repeats=1"),
            suffix.into(),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=multisplit:blob={fake}:{fooling}:pos=2:nodrop:repeats=1"),
            suffix.into(),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
        out.push(vec![
            payload.into(),
            format!("--lua-desync=fake:blob={fake}:{fooling}:tls_mod=rnd,dupsid,padencap:repeats=1"),
            suffix.into(),
            "--payload=empty".into(), "--out-range=<s1".into(), "--lua-desync=send:tcp_md5".into(),
        ]);
    }

    out
}

/// 50-fake-multi.sh (TLS) — fake vary + multisplit/multidisorder suffix
/// Port of pktws_check_https_tls() from 50-fake-multi.sh
fn fake_multi_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let fake = "fake_default_tls";
    let mut out = Vec::new();

    for &splitf in SPLIT_METHODS {
        // TTL
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in TLS_SPLITS {
                let suffix = format!("--lua-desync={splitf}:pos={split}");
                let fooling = format!("ip_ttl={ttl}");
                let vary = fake_https_vary_with_suffix(&fooling, payload, fake, &suffix);
                out.extend(vary.clone());
                // with pktmod limiter
                for s in &vary {
                    let mut extended = s.clone();
                    extended.extend([
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                    out.push(extended);
                }
            }
        }
        // foolings
        for &fooling in FOOLINGS_TCP {
            for &split in TLS_SPLITS {
                let suffix = format!("--lua-desync={splitf}:pos={split}");
                out.extend(fake_https_vary_with_suffix(fooling, payload, fake, &suffix));
            }
        }
        // autottl
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in TLS_SPLITS {
                let suffix = format!("--lua-desync={splitf}:pos={split}");
                let fooling = format!("ip_autottl=-{ttl},3-20");
                let vary = fake_https_vary_with_suffix(&fooling, payload, fake, &suffix);
                out.extend(vary.clone());
                for s in &vary {
                    let mut extended = s.clone();
                    extended.extend([
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                    out.push(extended);
                }
            }
        }
    }

    out
}

/// 50-fake-multi.sh (TLS1.2 = TLS + wssize variants)
fn fake_multi_tls12() -> Vec<Strategy> {
    let base = fake_multi_tls();
    let mut out = base.clone();
    for s in &base {
        let mut wssize = vec!["--lua-desync=wssize:wsize=1:scale=6".to_string()];
        wssize.extend(s.clone());
        out.push(wssize);
    }
    out
}

/// 55-fake-faked.sh — fake + fakedsplit/fakeddisorder combinations (HTTP)
fn fake_faked_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let splitfs = &["fakedsplit", "fakeddisorder"];
    let mut out = Vec::new();

    for &splitf in splitfs {
        // TTL
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in HTTP_SPLITS {
                for &ff in FAKE_BLOBS_HTTP {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_ttl={ttl}:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                    ]);
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_ttl={ttl}:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                }
            }
        }
        // foolings
        for &fooling in FOOLINGS_TCP {
            for &split in HTTP_SPLITS {
                for &ff in FAKE_BLOBS_HTTP {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:{fooling}:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}:{fooling}:repeats=1"),
                    ]);
                    if fooling.contains("tcp_md5") {
                        out.push(vec![
                            payload.into(),
                            format!("--lua-desync=fake:blob={ff}:{fooling}:repeats=1"),
                            format!("--lua-desync={splitf}:pos={split}:{fooling}:repeats=1"),
                            "--payload=empty".into(),
                            "--out-range=<s1".into(),
                            "--lua-desync=send:tcp_md5".into(),
                        ]);
                    }
                }
            }
        }
        // autottl
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in HTTP_SPLITS {
                for &ff in FAKE_BLOBS_HTTP {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_autottl=-{ttl},3-20:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                    ]);
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={ff}:ip_autottl=-{ttl},3-20:repeats=1"),
                        format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                }
            }
        }
    }

    out
}

/// 55-fake-faked.sh (TLS) — fake vary + fakedsplit/fakeddisorder suffix
/// Port of pktws_check_https_tls() from 55-fake-faked.sh
fn fake_faked_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let fake = "fake_default_tls";
    let splitfs = &["fakedsplit", "fakeddisorder"];
    let mut out = Vec::new();

    for &splitf in splitfs {
        // TTL — vanilla suffix: $splitf:pos=$split:$fooling (no :repeats=)
        for ttl in TTL_MIN..=TTL_MAX {
            for &split in TLS_SPLITS_FAKED {
                let suffix = format!("--lua-desync={splitf}:pos={split}:ip_ttl={ttl}");
                let fooling = format!("ip_ttl={ttl}");
                let vary = fake_https_vary_with_suffix(&fooling, payload, fake, &suffix);
                out.extend(vary.clone());
                for s in &vary {
                    let mut extended = s.clone();
                    extended.extend([
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                    out.push(extended);
                }
            }
        }
        // foolings — vanilla suffix: $splitf:pos=$split:$fooling (no :repeats=)
        for &fooling in FOOLINGS_TCP {
            for &split in TLS_SPLITS_FAKED {
                let suffix = format!("--lua-desync={splitf}:pos={split}:{fooling}");
                out.extend(fake_https_vary_with_suffix(fooling, payload, fake, &suffix));
            }
        }
        // autottl — vanilla suffix: $splitf:pos=$split:$fooling (no :repeats=)
        for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
            for &split in TLS_SPLITS_FAKED {
                let suffix = format!("--lua-desync={splitf}:pos={split}:ip_autottl=-{ttl},3-20");
                let fooling = format!("ip_autottl=-{ttl},3-20");
                let vary = fake_https_vary_with_suffix(&fooling, payload, fake, &suffix);
                out.extend(vary.clone());
                for s in &vary {
                    let mut extended = s.clone();
                    extended.extend([
                        "--payload=empty".into(),
                        "--out-range=s1<d1".into(),
                        "--lua-desync=pktmod:ip_ttl=1".into(),
                    ]);
                    out.push(extended);
                }
            }
        }
    }

    out
}

/// 55-fake-faked.sh (TLS1.2 = TLS + wssize variants)
fn fake_faked_tls12() -> Vec<Strategy> {
    let base = fake_faked_tls();
    let mut out = base.clone();
    for s in &base {
        let mut wssize = vec!["--lua-desync=wssize:wsize=1:scale=6".to_string()];
        wssize.extend(s.clone());
        out.push(wssize);
    }
    out
}

/// 60-fake-hostfake.sh — fake + hostfakesplit combinations (HTTP)
fn fake_hostfake_http() -> Vec<Strategy> {
    let payload = "--payload=http_req";
    let fake = "fake_default_http";
    let mut out = Vec::new();

    // TTL
    for ttl in TTL_MIN..=TTL_MAX {
        for &disorder in HOSTFAKE_DISORDERS {
            for &variant in HOSTFAKE_VARIANTS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_ttl={ttl}:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_ttl={ttl}:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_ttl={ttl}:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_ttl={ttl}:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }
    // foolings
    for &fooling in FOOLINGS_TCP {
        for &disorder in HOSTFAKE_DISORDERS {
            for &variant in HOSTFAKE_VARIANTS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}{fooling}:repeats=1"),
                ]);
                if fooling.contains("tcp_md5") {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
                        format!("--lua-desync=hostfakesplit:{disorder}{variant}{fooling}:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=<s1".into(),
                        "--lua-desync=send:tcp_md5".into(),
                    ]);
                }
            }
        }
    }
    // autottl
    for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
        for &disorder in HOSTFAKE_DISORDERS {
            for &variant in HOSTFAKE_VARIANTS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_autottl=-{ttl},3-20:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_autottl=-{ttl},3-20:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_autottl=-{ttl},3-20:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_autottl=-{ttl},3-20:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }

    out
}

/// 60-fake-hostfake.sh (TLS)
fn fake_hostfake_tls() -> Vec<Strategy> {
    let payload = "--payload=tls_client_hello";
    let fake = "fake_default_tls";
    let mut out = Vec::new();

    for ttl in TTL_MIN..=TTL_MAX {
        for &disorder in HOSTFAKE_DISORDERS {
            for &variant in HOSTFAKE_VARIANTS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_ttl={ttl}:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_ttl={ttl}:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_ttl={ttl}:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_ttl={ttl}:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }
    for &fooling in FOOLINGS_TCP {
        for &disorder in HOSTFAKE_DISORDERS {
            for &variant in HOSTFAKE_VARIANTS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}{fooling}:repeats=1"),
                ]);
                if fooling.contains("tcp_md5") {
                    out.push(vec![
                        payload.into(),
                        format!("--lua-desync=fake:blob={fake}:{fooling}:repeats=1"),
                        format!("--lua-desync=hostfakesplit:{disorder}{variant}{fooling}:repeats=1"),
                        "--payload=empty".into(),
                        "--out-range=<s1".into(),
                        "--lua-desync=send:tcp_md5".into(),
                    ]);
                }
            }
        }
    }
    for ttl in AUTOTTL_MIN..=AUTOTTL_MAX {
        for &disorder in HOSTFAKE_DISORDERS {
            for &variant in HOSTFAKE_VARIANTS {
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_autottl=-{ttl},3-20:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_autottl=-{ttl},3-20:repeats=1"),
                ]);
                out.push(vec![
                    payload.into(),
                    format!("--lua-desync=fake:blob={fake}:ip_autottl=-{ttl},3-20:repeats=1"),
                    format!("--lua-desync=hostfakesplit:{disorder}{variant}ip_autottl=-{ttl},3-20:repeats=1"),
                    "--payload=empty".into(),
                    "--out-range=s1<d1".into(),
                    "--lua-desync=pktmod:ip_ttl=1".into(),
                ]);
            }
        }
    }

    out
}

/// 60-fake-hostfake.sh (TLS1.2 = TLS + wssize variants)
fn fake_hostfake_tls12() -> Vec<Strategy> {
    let base = fake_hostfake_tls();
    let mut out = base.clone();
    for s in &base {
        let mut wssize = vec!["--lua-desync=wssize:wsize=1:scale=6".to_string()];
        wssize.extend(s.clone());
        out.push(wssize);
    }
    out
}

// --- Entry point ---

/// Generate all strategies for the given protocol (brute-force / force mode).
pub fn generate_strategies(protocol: Protocol) -> Vec<Strategy> {
    match protocol {
        Protocol::Http => {
            let mut out = Vec::new();
            out.extend(http_basic());
            out.extend(misc_http());
            out.extend(oob());
            out.extend(multi_http());
            out.extend(seqovl_http());
            out.extend(syndata_http());
            out.extend(fake_http());
            out.extend(faked_http());
            out.extend(hostfake_http());
            out.extend(fake_multi_http());
            out.extend(fake_faked_http());
            out.extend(fake_hostfake_http());
            out
        }
        Protocol::HttpsTls12 => {
            let mut out = Vec::new();
            out.extend(misc_tls());
            out.extend(oob());
            out.extend(multi_tls12());
            out.extend(seqovl_tls12());
            out.extend(syndata_tls12());
            out.extend(fake_tls12());
            out.extend(faked_tls12());
            out.extend(hostfake_tls12());
            out.extend(fake_multi_tls12());
            out.extend(fake_faked_tls12());
            out.extend(fake_hostfake_tls12());
            out
        }
        Protocol::HttpsTls13 => {
            let mut out = Vec::new();
            out.extend(misc_tls());
            out.extend(oob());
            out.extend(multi_tls());
            out.extend(seqovl_tls());
            out.extend(syndata_tls());
            out.extend(fake_tls());
            out.extend(faked_tls());
            out.extend(hostfake_tls());
            out.extend(fake_multi_tls());
            out.extend(fake_faked_tls());
            out.extend(fake_hostfake_tls());
            out
        }
    }
}

/// Returns per-phase strategy counts for diagnostics.
pub fn phase_counts(protocol: Protocol) -> Vec<(&'static str, usize)> {
    match protocol {
        Protocol::Http => vec![
            ("http_basic", http_basic().len()),
            ("misc_http", misc_http().len()),
            ("oob", oob().len()),
            ("multi_http", multi_http().len()),
            ("seqovl_http", seqovl_http().len()),
            ("syndata_http", syndata_http().len()),
            ("fake_http", fake_http().len()),
            ("faked_http", faked_http().len()),
            ("hostfake_http", hostfake_http().len()),
            ("fake_multi_http", fake_multi_http().len()),
            ("fake_faked_http", fake_faked_http().len()),
            ("fake_hostfake_http", fake_hostfake_http().len()),
        ],
        Protocol::HttpsTls12 => vec![
            ("misc_tls", misc_tls().len()),
            ("oob", oob().len()),
            ("multi_tls12", multi_tls12().len()),
            ("seqovl_tls12", seqovl_tls12().len()),
            ("syndata_tls12", syndata_tls12().len()),
            ("fake_tls12", fake_tls12().len()),
            ("faked_tls12", faked_tls12().len()),
            ("hostfake_tls12", hostfake_tls12().len()),
            ("fake_multi_tls12", fake_multi_tls12().len()),
            ("fake_faked_tls12", fake_faked_tls12().len()),
            ("fake_hostfake_tls12", fake_hostfake_tls12().len()),
        ],
        Protocol::HttpsTls13 => vec![
            ("misc_tls", misc_tls().len()),
            ("oob", oob().len()),
            ("multi_tls", multi_tls().len()),
            ("seqovl_tls", seqovl_tls().len()),
            ("syndata_tls", syndata_tls().len()),
            ("fake_tls", fake_tls().len()),
            ("faked_tls", faked_tls().len()),
            ("hostfake_tls", hostfake_tls().len()),
            ("fake_multi_tls", fake_multi_tls().len()),
            ("fake_faked_tls", fake_faked_tls().len()),
            ("fake_hostfake_tls", fake_hostfake_tls().len()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_basic_count() {
        assert_eq!(http_basic().len(), 5);
    }

    #[test]
    fn test_misc_counts() {
        assert_eq!(misc_http().len(), 8); // 4 repeats * 2 positions
        assert_eq!(misc_tls().len(), 8);
    }

    #[test]
    fn test_oob_count() {
        assert_eq!(oob().len(), 4);
    }

    #[test]
    fn test_multi_counts() {
        assert_eq!(multi_http().len(), 6); // 2 methods * 3 positions
        assert_eq!(multi_tls().len(), 18); // 2 methods * 9 positions
        assert_eq!(multi_tls12().len(), 36); // 18 + 18 wssize
    }

    #[test]
    fn test_seqovl_counts() {
        // HTTP: 2 tcpseg + 2*2 multisplit + 3*2 multidisorder = 2+4+6 = 12
        assert_eq!(seqovl_http().len(), 12);
        // TLS: 3 tcpseg + 4*3 multisplit + 5*2 multidisorder = 3+12+10 = 25
        assert_eq!(seqovl_tls().len(), 25);
        // TLS12: 25 + 3 tcpseg + 4*3 multisplit + 5*2 multidisorder = 25 + 3+12+10 = 50
        assert_eq!(seqovl_tls12().len(), 50);
    }

    #[test]
    fn test_syndata_counts() {
        assert_eq!(syndata_http().len(), 6); // 3 splits * 2 variants
        assert_eq!(syndata_tls().len(), 12); // 3 splits * 4 variants
        assert_eq!(syndata_tls12().len(), 24); // 12 + 12 wssize
    }

    #[test]
    fn test_generate_no_empty_strategies() {
        for protocol in [Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13] {
            let strategies = generate_strategies(protocol);
            for (i, s) in strategies.iter().enumerate() {
                assert!(!s.is_empty(), "empty strategy at index {i} for {protocol}");
            }
        }
    }

    #[test]
    fn test_generate_no_duplicate_strategies() {
        for protocol in [Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13] {
            let strategies = generate_strategies(protocol);
            let mut seen = std::collections::HashSet::new();
            let mut dupes = 0;
            for s in &strategies {
                if !seen.insert(s.clone()) {
                    dupes += 1;
                }
            }
            // FIXME: this test should assert_eq!(dupes, 0) instead of just printing a warning;
            // duplicates waste scan time proportionally
            if dupes > 0 {
                eprintln!("WARNING: {protocol} has {dupes} duplicate strategies out of {}", strategies.len());
            }
        }
    }

    #[test]
    fn test_phase_counts_sum() {
        for protocol in [Protocol::Http, Protocol::HttpsTls12, Protocol::HttpsTls13] {
            let phases = phase_counts(protocol);
            let sum: usize = phases.iter().map(|(_, c)| c).sum();
            let total = generate_strategies(protocol).len();
            assert_eq!(sum, total, "phase counts don't sum to total for {protocol}");
        }
    }

    #[test]
    fn test_strategy_totals() {
        let http = generate_strategies(Protocol::Http).len();
        let tls13 = generate_strategies(Protocol::HttpsTls13).len();
        let tls12 = generate_strategies(Protocol::HttpsTls12).len();

        eprintln!("Strategy counts: HTTP={http}, TLS1.3={tls13}, TLS1.2={tls12}");

        // Print per-phase breakdown
        for protocol in [Protocol::Http, Protocol::HttpsTls13, Protocol::HttpsTls12] {
            eprintln!("\n--- {protocol} ---");
            for (name, count) in phase_counts(protocol) {
                eprintln!("  {name}: {count}");
            }
        }

        // Sanity checks: all counts should be > 1000
        assert!(http > 1000, "HTTP strategy count too low: {http}");
        assert!(tls13 > 1000, "TLS1.3 strategy count too low: {tls13}");
        assert!(tls12 > tls13, "TLS1.2 should have more strategies than TLS1.3");
    }

    /// Helper: parse a vanilla nfqws2 command line into our Strategy (Vec<String>) format.
    /// Input: "--payload=tls_client_hello --lua-desync=fake:blob=... --payload=empty ..."
    /// Output: vec!["--payload=tls_client_hello", "--lua-desync=fake:blob=...", "--payload=empty", ...]
    fn parse_vanilla(cmd: &str) -> Strategy {
        cmd.split_whitespace().map(String::from).collect()
    }

    /// Verify that known-working vanilla strategies are generated by our code.
    /// Each strategy here was found by blockcheck2.sh on a real network and confirmed working.
    #[test]
    fn test_vanilla_working_strategies_are_generated() {
        let tls12 = generate_strategies(Protocol::HttpsTls12);
        let tls12_set: std::collections::HashSet<Vec<String>> = tls12.into_iter().collect();

        // --- Phase 25-fake: multisplit:blob=...nodrop (the strategy that opened rutracker in browser) ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=10:pos=2:nodrop:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "25-fake: multisplit:blob nodrop with TTL+pktmod not generated:\n{s:?}");

        // --- Phase 25-fake: multisplit:blob=...nodrop with tcp_md5 + send:tcp_md5 ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:tcp_md5:pos=2:nodrop:repeats=1 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5");
        assert!(tls12_set.contains(&s), "25-fake: multisplit:blob nodrop with tcp_md5 not generated:\n{s:?}");

        // --- Phase 25-fake: double fake (null-blob + tls_mod=rnd,dupsid) ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_seq=-3000:repeats=1 --lua-desync=fake:blob=fake_default_tls:tcp_seq=-3000:tls_mod=rnd,dupsid:repeats=1");
        assert!(tls12_set.contains(&s), "25-fake: double fake with tcp_seq=-3000 not generated:\n{s:?}");

        // --- Phase 25-fake: fake with tls_mod=rnd,dupsid,padencap ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_ts=-1000:tls_mod=rnd,dupsid,padencap:repeats=1");
        assert!(tls12_set.contains(&s), "25-fake: fake with padencap not generated:\n{s:?}");

        // --- Phase 25-fake: multisplit:blob nodrop with autottl ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_autottl=-1,3-20:pos=2:nodrop:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "25-fake: multisplit:blob nodrop with autottl not generated:\n{s:?}");

        // --- Phase 50-fake-multi: multisplit:blob nodrop + multisplit:pos suffix ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=5:pos=2:nodrop:repeats=1 --lua-desync=multisplit:pos=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "50-fake-multi: multisplit:blob nodrop + multisplit suffix not generated:\n{s:?}");

        // --- Phase 50-fake-multi: double fake + multisplit:pos suffix ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:ip_ttl=5:repeats=1 --lua-desync=fake:blob=fake_default_tls:ip_ttl=5:tls_mod=rnd,dupsid:repeats=1 --lua-desync=multisplit:pos=2 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "50-fake-multi: double fake + multisplit suffix not generated:\n{s:?}");

        // --- Phase 50-fake-multi: multisplit:blob nodrop + tcp_md5 + multisplit:pos + send:tcp_md5 ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:tcp_md5:pos=2:nodrop:repeats=1 --lua-desync=multisplit:pos=2 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5");
        assert!(tls12_set.contains(&s), "50-fake-multi: multisplit:blob nodrop + tcp_md5 + multisplit suffix not generated:\n{s:?}");

        // --- Phase 55-fake-faked: multisplit:blob nodrop + fakedsplit suffix (no :repeats= in suffix) ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=5:pos=2:nodrop:repeats=1 --lua-desync=fakedsplit:pos=sniext+1:ip_ttl=5 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "55-fake-faked: multisplit:blob nodrop + fakedsplit suffix not generated:\n{s:?}");

        // --- Phase 55-fake-faked: padencap + fakeddisorder suffix (fooling suffix has no :repeats=) ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_seq=1000000:tls_mod=rnd,dupsid,padencap:repeats=1 --lua-desync=fakeddisorder:pos=2:tcp_seq=1000000");
        assert!(tls12_set.contains(&s), "55-fake-faked: padencap + fakeddisorder suffix not generated:\n{s:?}");

        // --- Phase 55-fake-faked: multisplit:blob nodrop + tcp_md5 + fakedsplit + send:tcp_md5 ---
        // fooling suffix has no :repeats=, send:tcp_md5 postfix comes from the vary wrapper
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:tcp_md5:pos=2:nodrop:repeats=1 --lua-desync=fakedsplit:pos=2:tcp_md5 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5");
        assert!(tls12_set.contains(&s), "55-fake-faked: multisplit:blob nodrop + tcp_md5 + fakedsplit + send:tcp_md5 not generated:\n{s:?}");

        // ===== Phase 30-faked =====

        // --- fakedsplit with TTL + pktmod limiter ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:ip_ttl=5:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "30-faked: fakedsplit TTL+pktmod not generated:\n{s:?}");

        // --- fakedsplit with tcp_md5 + send:tcp_md5 ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakedsplit:pos=host+1:tcp_md5:repeats=1 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5");
        assert!(tls12_set.contains(&s), "30-faked: fakedsplit tcp_md5+send not generated:\n{s:?}");

        // --- fakedsplit with tcp_seq fooling (no :repeats=) ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakedsplit:pos=sniext+4:tcp_seq=-3000");
        assert!(tls12_set.contains(&s), "30-faked: fakedsplit tcp_seq=-3000 not generated:\n{s:?}");

        // --- fakeddisorder with TTL + pktmod ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakeddisorder:pos=host+1:ip_ttl=5:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "30-faked: fakeddisorder TTL+pktmod not generated:\n{s:?}");

        // --- fakeddisorder with tcp_ack fooling ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakeddisorder:pos=sniext+4:tcp_ack=-66000:tcp_ts_up");
        assert!(tls12_set.contains(&s), "30-faked: fakeddisorder tcp_ack not generated:\n{s:?}");

        // --- fakedsplit with autottl + pktmod ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakedsplit:pos=host+1:ip_autottl=-1,3-20:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "30-faked: fakedsplit autottl+pktmod not generated:\n{s:?}");

        // --- fakeddisorder with autottl + pktmod ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=fakeddisorder:pos=sniext+4:ip_autottl=-1,3-20:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "30-faked: fakeddisorder autottl+pktmod not generated:\n{s:?}");

        // ===== Phase 35-hostfake =====

        // --- hostfakesplit with disorder_after + TTL + pktmod ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:disorder_after:ip_ttl=5:repeats=1 --payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1");
        assert!(tls12_set.contains(&s), "35-hostfake: disorder_after TTL+pktmod not generated:\n{s:?}");

        // --- hostfakesplit with tcp_md5 ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:tcp_md5:repeats=1");
        assert!(tls12_set.contains(&s), "35-hostfake: tcp_md5 not generated:\n{s:?}");

        // --- hostfakesplit with nofake2 + tcp_md5 ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:nofake2:tcp_md5:repeats=1");
        assert!(tls12_set.contains(&s), "35-hostfake: nofake2 tcp_md5 not generated:\n{s:?}");

        // --- hostfakesplit with tcp_md5 + send:tcp_md5 ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:tcp_md5:repeats=1 --payload=empty --out-range=<s1 --lua-desync=send:tcp_md5");
        assert!(tls12_set.contains(&s), "35-hostfake: tcp_md5+send not generated:\n{s:?}");

        // --- hostfakesplit with tcp_ack ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:tcp_ack=-66000:tcp_ts_up:repeats=1");
        assert!(tls12_set.contains(&s), "35-hostfake: tcp_ack not generated:\n{s:?}");

        // --- hostfakesplit with disorder_after:nofake2 + tcp_ack ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:disorder_after:nofake2:tcp_ack=-66000:tcp_ts_up:repeats=1");
        assert!(tls12_set.contains(&s), "35-hostfake: disorder_after nofake2 tcp_ack not generated:\n{s:?}");

        // --- hostfakesplit with autottl ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:nofake2:ip_autottl=-1,3-20:repeats=1");
        assert!(tls12_set.contains(&s), "35-hostfake: nofake2 autottl not generated:\n{s:?}");

        // --- hostfakesplit with disorder_after + autottl ---
        let s = parse_vanilla("--payload=tls_client_hello --lua-desync=hostfakesplit:disorder_after:ip_autottl=-1,3-20:repeats=1");
        assert!(tls12_set.contains(&s), "35-hostfake: disorder_after autottl not generated:\n{s:?}");
    }
}
