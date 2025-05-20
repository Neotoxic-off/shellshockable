use clap::Parser;

#[derive(Parser)]
#[command(version, about = "Shellshockable, we never know")]
pub struct Arguments {
    #[arg(short, long = "vuln-file")]
    pub vuln_file: String,

    #[arg(short, long)]
    pub uri: String
}
