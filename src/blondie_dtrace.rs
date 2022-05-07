// Binary to run cargo-flamegraph using blondie, which pretends to be dtrace

fn main() -> Result<(), blondie::Error> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let dash_c_idx = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_str().unwrap() == "-c")
        .next()
        .unwrap()
        .0;
    let args = &args[dash_c_idx + 1..];
    let mut _args_v = vec![];
    let mut arg0 = args[0].clone();
    let mut other_args = &args[1..];
    if other_args.is_empty() {
        let mut it = arg0.to_str().unwrap().split_whitespace();
        let arg0_str = std::ffi::OsStr::new(it.next().unwrap());
        _args_v = it
            .map(|s| std::ffi::OsStr::new(s).to_os_string())
            .collect::<Vec<_>>();
        other_args = &_args_v[..];
        arg0 = arg0_str.to_os_string();
    }

    let mut c = std::process::Command::new(&arg0);
    c.args(other_args);
    let kernel_stacks = false;
    let trace_ctx = blondie::trace_command(c, kernel_stacks)?;

    let f = std::fs::File::create("./cargo-flamegraph.stacks").expect("Unable to create file");
    let mut f = std::io::BufWriter::new(f);
    trace_ctx.write_dtrace(&mut f)?;

    Ok(())
}
