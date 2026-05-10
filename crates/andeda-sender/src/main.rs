use clap::Parser;

fn main() {
    let cli = andeda_sender::cli::Cli::parse();
    match cli.command {
        andeda_sender::cli::Command::Start => {
            eprintln!("[INFO] sender start (not yet wired)");
        }
        andeda_sender::cli::Command::Doctor => {
            eprintln!("[INFO] sender doctor (not yet wired)");
        }
        andeda_sender::cli::Command::DryRun { url } => {
            eprintln!("[INFO] sender dry-run url={url} (not yet wired)");
        }
    }
}
