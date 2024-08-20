use std::process::Command;

#[test]
fn test_basic() {
    let mut cmd = Command::new("ping");
    cmd.arg("localhost");
    let result = blondie::trace_command(cmd, false).unwrap();
    assert!(0 < result.iter_callstacks().count());
}
