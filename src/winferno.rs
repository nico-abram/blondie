// Binary to run winstacks and generate a flamegraph using inferno from the trace

use inferno::collapse::Collapse;

fn main() -> Result<(), winstacks::Error> {
    let mut args = std::env::args_os().skip(1);
    let arg0 = args
        .next()
        .expect("Expected command to run.\nUSAGE: winferno.exe [command] [command args...]");
    let trace_ctx = winstacks::trace_command(arg0, &args.collect::<Vec<_>>())?;

    let mut trace_output = Vec::new();
    trace_ctx.write_dtrace(&mut trace_output)?;
    std::fs::write("./trace_output", &trace_output).unwrap();

    let mut collapsed_output = Vec::new();
    let mut collapse_options = inferno::collapse::dtrace::Options::default();
    inferno::collapse::dtrace::Folder::from(collapse_options)
        .collapse(&trace_output[..], &mut collapsed_output)
        .expect("unable to collapse generated profile data");
    std::fs::write("./collapsed_output", &collapsed_output).unwrap();
    let flamegraph_file =
        std::fs::File::create("./winferno_flamegraph.svg").expect("Error creating flamegraph file");
    let flamegraph_writer = std::io::BufWriter::new(flamegraph_file);
    let mut inferno_opts = inferno::flamegraph::Options::default();
    inferno::flamegraph::from_reader(&mut inferno_opts, &collapsed_output[..], flamegraph_writer)
        .expect("unable to generate a flamegraph from the collapsed stack data");

    Ok(())
}
