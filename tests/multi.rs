use std::process::Command;

#[test]
fn test_multi() {
    let handle = std::thread::spawn(|| {
        let mut cmd = Command::new("ping");
        cmd.arg("localhost");
        let _ctx = blondie::trace_command(cmd, false).unwrap();
    });

    let mut cmd = Command::new("ping");
    cmd.arg("localhost");
    let _ctx = blondie::trace_command(cmd, false).unwrap();

    handle.join().unwrap();
}
