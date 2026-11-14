//! morpheus-certificate-install 0.4.2 — the click tests' reference connection to the fake
//! appliance (tests/click/lib/vm.mjs). The click suites drive the app's page; to set the VM up and
//! check it afterwards they need a second, independent connection, as engine_e2e has. This test is
//! that connection: it runs MCI_CLICK_REF (a shell script, test-only text kept in
//! tests/click/lib/vm.mjs) as root over its own SSH session and prints stdout and the exit code
//! between markers. It does nothing without MCI_CLICK_REF, so it's harmless in a normal run.
//!
//!   MCI_TEST_SSH=… MCI_CLICK_REF='…' cargo test -p morpheus-certificate-install --test click_ref -- --ignored --nocapture

mod common;

#[test]
#[ignore = "the click tests' reference connection: MCI_TEST_SSH and MCI_CLICK_REF"]
fn click_ref() {
    let Ok(script) = std::env::var("MCI_CLICK_REF") else { eprintln!("MCI_CLICK_REF not set"); return };
    let tg = common::ssh_target().expect("MCI_TEST_SSH=host:port:user:password");
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let t = common::ssh_reference(&tg).await;
        let as_root = std::env::var("MCI_CLICK_REF_USER").map(|v| v != "1").unwrap_or(true);
        let r = t.run_data(&script, as_root, None, 120).await.expect("reference run");
        println!("@@CLICKREF-BEGIN\n{}@@CLICKREF-END rc={}", r.stdout, r.rc);
        if r.rc != 0 { eprintln!("stderr: {}", r.complaint(2000)); }
        t.close().await;
    });
}
