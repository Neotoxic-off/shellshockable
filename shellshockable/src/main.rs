mod arguments;
mod scanner;
mod logger;
mod types;

use crate::arguments::Arguments;
use crate::logger::init_logger;
use crate::scanner::run_scanner;
use clap::Parser;

#[tokio::main]
async fn main() {
    init_logger();

    let args = Arguments::parse();
    run_scanner(args).await;
}
