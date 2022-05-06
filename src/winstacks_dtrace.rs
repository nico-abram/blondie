// Binary to run cargo-flamegraph using winstacks, which pretends to be dtrace

fn main() -> Result<(), winstacks::Error> {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let dash_c_idx = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_str().unwrap() == "-c")
        .next()
        .unwrap()
        .0;
    let args = &args[dash_c_idx + 1..];
    let trace_ctx = winstacks::trace_command(args[0].clone(), &args[1..])?;

    let f = std::fs::File::create("./cargo-flamegraph.stacks").expect("Unable to create file");
    let mut f = std::io::BufWriter::new(f);
    trace_ctx.write_dtrace(&mut f)?;

    Ok(())
}
