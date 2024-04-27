use std::ffi::OsString;

use clap::Parser;
use inferno::collapse::Collapse;

#[derive(Parser, Debug)]
#[clap(name = "blondie")]
#[clap(bin_name = "blondie")]
#[clap(author = "Nicolas Abram Lujan <abramlujan@gmail.com>")]
#[clap(version = "0.1-alpha2")]
#[clap(about = "CPU call stack sampling", long_about = None)]
struct Blondie {
    /// If kernel stacks should be included in the output
    #[clap(short, long)]
    kernel_stacks: bool,
    /// Output filename
    #[clap(short, long, value_parser)]
    out: Option<std::path::PathBuf>,
    /// Don't redirect stdout/stderr from the target process to blondie
    #[clap(short, long)]
    no_redirect: bool,

    #[clap(subcommand)]
    subcommand: Subcommands,
}
#[derive(clap::Subcommand, Debug)]
enum Subcommands {
    /// Generate a flamegraph. Default output is ./flamegraph.svg
    #[clap(trailing_var_arg = true)]
    Flamegraph {
        /// Output filename for trace text callstacks. Defaults to nowhere.
        #[clap(short, long, value_parser)]
        trace_file: Option<std::path::PathBuf>,
        /// Output filename for inferno collapsed stacks. Defaults to nowhere.
        #[clap(short, long, value_parser)]
        collapsed_file: Option<std::path::PathBuf>,
        /// The command to run
        command: OsString,
        /// Arguments for the command to run
        args: Vec<OsString>,
    },
    /// Generate a text file with the folded callstacks. Default output is ./folded_stacks.txt
    #[clap(trailing_var_arg = true)]
    FoldedText {
        /// The command to run
        command: OsString,
        /// Arguments for the command to run
        args: Vec<OsString>,
    },
}

fn main() -> Result<(), blondie::Error> {
    let args = Blondie::parse();

    let (command, command_args) = match &args.subcommand {
        Subcommands::Flamegraph { command, args, .. } => (command.clone(), args.clone()),
        Subcommands::FoldedText { command, args } => (command.clone(), args.clone()),
    };
    let mut command_builder = std::process::Command::new(command);
    command_builder.args(command_args);
    if args.no_redirect {
        command_builder.stdout(std::process::Stdio::null());
        command_builder.stderr(std::process::Stdio::null());
    }
    let trace_ctx = blondie::trace_command(command_builder, args.kernel_stacks)?;

    match &args.subcommand {
        Subcommands::Flamegraph {
            trace_file,
            collapsed_file,
            ..
        } => {
            let filename = args.out.unwrap_or("./flamegraph.svg".into());

            let mut trace_output = Vec::new();
            trace_ctx.write_dtrace(&mut trace_output)?;
            if let Some(trace_file) = trace_file {
                std::fs::write(trace_file, &trace_output).unwrap();
            }

            println!("Wrote dtrace output to {:?}",trace_file);
            

            let mut collapsed_output = Vec::new();
            let collapse_options = inferno::collapse::dtrace::Options::default();
            inferno::collapse::dtrace::Folder::from(collapse_options)
                .collapse(&trace_output[..], &mut collapsed_output)
                .expect("unable to collapse generated profile data");
            if let Some(collapsed_file) = collapsed_file {
                std::fs::write(collapsed_file, &collapsed_output).unwrap();
            }

            let flamegraph_file = std::fs::File::create(&filename).expect(&format!(
                "Error creating flamegraph file {}",
                filename.into_os_string().into_string().unwrap()
            ));
            let flamegraph_writer = std::io::BufWriter::new(flamegraph_file);
            let mut inferno_opts = inferno::flamegraph::Options::default();
            inferno::flamegraph::from_reader(
                &mut inferno_opts,
                &collapsed_output[..],
                flamegraph_writer,
            )
            .expect("unable to generate a flamegraph from the collapsed stack data");
        }
        Subcommands::FoldedText { .. } => {
            let filename = args.out.unwrap_or("./folded_stacks.txt".into());

            let f = std::fs::File::create(&filename).expect(&format!(
                "Unable to create file {}",
                filename.into_os_string().into_string().unwrap()
            ));
            let mut f = std::io::BufWriter::new(f);

            trace_ctx.write_dtrace(&mut f)?;
        }
    };

    Ok(())
}
