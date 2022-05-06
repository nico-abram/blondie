// Binary to run a command under winstacks and generate a file with all the collected call stacks and their counts

fn main() -> Result<(), winstacks::Error> {
    let mut args = std::env::args_os().skip(1);
    let arg0 = args
        .next()
        .expect("Expected command to run.\nUSAGE: winstack.exe [command] [command args...]");
    let trace_ctx = winstacks::trace_command(arg0, &args.collect::<Vec<_>>())?;

    let f = std::fs::File::create("./out.stacks").expect("Unable to create file");
    let mut f = std::io::BufWriter::new(f);
    trace_ctx.write_dtrace(&mut f)?;

    Ok(())
}
