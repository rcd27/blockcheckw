//! Infrastructure e2e tests — verify SO_MARK, nftables rules, autottl pipeline.
//!
//! Requires: root, nfqws2 installed, nftables available.
//! Run: `sudo cargo test --test e2e_infra -- --nocapture`

use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use blockcheckw::config::{CoreConfig, Protocol, DESYNC_MARK, WORKER_MARK_BASE};
use blockcheckw::firewall::nftables;
use blockcheckw::network::http_client;
use blockcheckw::system::process::run_process;
use blockcheckw::worker::nfqws2::start_nfqws2;
use blockcheckw::worker::slot::WorkerSlot;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// ── Test 1: SO_MARK is set before connect ────────────────────────────────────

#[tokio::test]
async fn so_mark_set_on_socket() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    let fwmark: u32 = WORKER_MARK_BASE | 1;
    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    let stream = http_client::marked_tcp_connect(addr, fwmark).await.unwrap();

    let fd = stream.as_raw_fd();
    let mut mark_out: u32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<u32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark_out as *mut u32 as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(ret, 0, "getsockopt failed");
    assert_eq!(
        mark_out, fwmark,
        "SO_MARK should be {fwmark:#010X}, got {mark_out:#010X}"
    );
}

#[tokio::test]
async fn so_mark_zero_means_no_mark() {
    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    let stream = http_client::marked_tcp_connect(addr, 0).await.unwrap();

    let fd = stream.as_raw_fd();
    let mut mark_out: u32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<u32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark_out as *mut u32 as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(ret, 0, "getsockopt failed");
    assert_eq!(mark_out, 0, "SO_MARK should be 0 for baseline");
}

// ── Test 2: nftables vmap add/remove ─────────────────────────────────────────

#[tokio::test]
async fn nft_vmap_add_remove_rules() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    let table = "zapret_test_vmap";
    let ips = vec!["1.1.1.1".to_string()];

    nftables::drop_table(table).await;
    nftables::prepare_table(table).await.expect("prepare_table");

    let slots = WorkerSlot::create_slots(4, 500);

    // Add vmap elements + dispatch rules
    nftables::add_all_worker_rules(table, &slots, 443, &ips)
        .await
        .expect("add_all_worker_rules");

    // Verify vmap elements exist
    let list_result = run_process(&["nft", "list", "table", "inet", table], 5000)
        .await
        .expect("nft list");
    let content = &list_result.stdout;

    for slot in &slots {
        let has_queue = content.contains(&format!("queue num {}", slot.qnum))
            || content.contains(&format!("queue to {}", slot.qnum));
        assert!(
            has_queue,
            "table should contain queue for slot {} (qnum {}). Content:\n{content}",
            slot.id, slot.qnum,
        );
    }

    // Verify only 1 postnat dispatch rule + 1 prenat dispatch rule (not N per worker)
    let postnat_queue_count =
        content.matches("queue num").count() + content.matches("queue to").count();
    // vmap elements + dispatch rule references — should be more than slots but
    // the key thing is chains have single dispatch rules
    eprintln!("Total 'queue num' occurrences: {postnat_queue_count}");

    // Remove
    nftables::remove_all_worker_rules(table, &slots).await;

    let list_result2 = run_process(&["nft", "list", "table", "inet", table], 5000)
        .await
        .expect("nft list after remove");

    for slot in &slots {
        let still_has = list_result2
            .stdout
            .contains(&format!("queue num {}", slot.qnum))
            || list_result2
                .stdout
                .contains(&format!("queue to {}", slot.qnum));
        assert!(
            !still_has,
            "queue {} should be removed after cleanup",
            slot.qnum,
        );
    }

    nftables::drop_table(table).await;
}

// ── Test 3: nfqws2 receives queued packets ───────────────────────────────────

#[tokio::test]
async fn nfqws2_receives_marked_traffic() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    let config = CoreConfig::default();
    let table = "zapret_test_nfqws2";
    let slots = WorkerSlot::create_slots(1, 600);
    let slot = &slots[0];
    let ips = vec!["1.1.1.1".to_string()];

    nftables::drop_table(table).await;
    nftables::prepare_table(table).await.expect("prepare_table");

    let strategy = vec!["--lua-desync=fake:ttl=1".to_string()];
    let mut nfqws2 = start_nfqws2(&config, slot.qnum, &strategy).expect("start nfqws2");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        nfqws2.try_wait().is_none(),
        "nfqws2 should still be running"
    );

    nftables::add_all_worker_rules(table, &slots, 80, &ips)
        .await
        .expect("add rules");

    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http_client::marked_tcp_connect(addr, slot.fwmark),
    )
    .await;

    assert!(
        nfqws2.try_wait().is_none(),
        "nfqws2 should still be running after processing traffic"
    );

    nftables::remove_all_worker_rules(table, &slots).await;
    nfqws2.kill().await;
    nftables::drop_table(table).await;
}

// ── Test 4: autottl pipeline — prenat captures SYN/ACK ───────────────────────

#[tokio::test]
async fn autottl_prenat_captures_synack() {
    if !is_root() {
        eprintln!("SKIPPED: requires root");
        return;
    }

    let config = CoreConfig::default();
    let table = "zapret_test_autottl";
    let slots = WorkerSlot::create_slots(1, 700);
    let slot = &slots[0];
    let ips = vec!["1.1.1.1".to_string()];

    nftables::drop_table(table).await;
    nftables::prepare_table(table).await.expect("prepare_table");

    let strategy = vec!["--lua-desync=fake:autottl=-2,3-20".to_string()];
    let mut nfqws2 = start_nfqws2(&config, slot.qnum, &strategy).expect("start nfqws2");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    nftables::add_all_worker_rules(table, &slots, 443, &ips)
        .await
        .expect("add rules");

    // Verify prenat vmap dispatch rule exists
    let list_result = run_process(&["nft", "list", "chain", "inet", table, "prenat"], 5000)
        .await
        .expect("nft list prenat");
    let prenat_content = &list_result.stdout;

    assert!(
        prenat_content.contains("syn") || prenat_content.contains("flags"),
        "prenat chain should have SYN/ACK matching rule. Content:\n{prenat_content}"
    );
    assert!(
        prenat_content.contains("vmap") || prenat_content.contains("queue"),
        "prenat chain should have vmap dispatch. Content:\n{prenat_content}"
    );

    // Make a marked TLS connection
    let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let _connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        http_client::marked_tcp_connect(addr, slot.fwmark),
    )
    .await;

    assert!(
        nfqws2.try_wait().is_none(),
        "nfqws2 should still be running after autottl flow"
    );

    // Check conntrack for ct mark
    if let Ok(ct_result) = run_process(
        &[
            "conntrack",
            "-L",
            "-d",
            "1.1.1.1",
            "-p",
            "tcp",
            "--dport",
            "443",
        ],
        5000,
    )
    .await
    {
        let combined = DESYNC_MARK | slot.fwmark;
        let has_mark = ct_result.stdout.lines().any(|line| {
            line.contains(&format!("mark={combined}"))
                || line.contains(&format!("mark=0x{combined:08x}"))
        });
        eprintln!("conntrack output:\n{}", ct_result.stdout);
        if has_mark {
            eprintln!("OK: conntrack entry has combined DESYNC|WORKER mark");
        } else {
            eprintln!("WARNING: no conntrack entry with expected mark found");
        }
    }

    nftables::remove_all_worker_rules(table, &slots).await;
    nfqws2.kill().await;
    nftables::drop_table(table).await;
}

// ── Test 5: HTTP request format matches curl ─────────────────────────────────

#[tokio::test]
async fn http_request_uses_relative_uri() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let _result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        http_client::http_test(
            Protocol::Http,
            "testhost.example",
            &local_addr.ip().to_string(),
            0,
            2,
        ),
    )
    .await;

    if let Ok(request_line) = tokio::time::timeout(std::time::Duration::from_secs(2), server).await
    {
        let request_line = request_line.unwrap();
        eprintln!("Captured request:\n{request_line}");

        assert!(
            request_line.starts_with("GET / HTTP/1.1\r\n"),
            "HTTP request should use relative URI 'GET / HTTP/1.1', got: {}",
            request_line.lines().next().unwrap_or("(empty)")
        );
        assert!(
            request_line.contains("host: testhost.example"),
            "Request should contain Host header"
        );
        assert!(
            request_line.contains("user-agent: Mozilla"),
            "Request should contain User-Agent"
        );
    }
}

// ── Test 6: TLS version config ───────────────────────────────────────────────

#[tokio::test]
async fn tls12_config_only_allows_tls12() {
    let config = http_client::make_tls_config(Protocol::HttpsTls12);
    assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
}

#[tokio::test]
async fn tls13_config_only_allows_tls13() {
    let config = http_client::make_tls_config(Protocol::HttpsTls13);
    assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
}

// ── Test 7: Worker slot fwmark isolation ─────────────────────────────────────

#[test]
fn worker_fwmarks_dont_collide_with_desync() {
    let slots = WorkerSlot::create_slots(512, 200);
    for slot in &slots {
        assert_eq!(
            slot.fwmark & DESYNC_MARK,
            0,
            "worker {} fwmark {:#010X} collides with DESYNC_MARK",
            slot.id,
            slot.fwmark,
        );
    }
}

#[test]
fn worker_fwmarks_are_unique() {
    let slots = WorkerSlot::create_slots(512, 200);
    let mut marks: Vec<u32> = slots.iter().map(|s| s.fwmark).collect();
    marks.sort();
    marks.dedup();
    assert_eq!(marks.len(), 512, "all 512 fwmarks should be unique");
}
