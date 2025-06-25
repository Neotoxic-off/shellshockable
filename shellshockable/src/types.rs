use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
pub struct ShellshockPaths(pub HashMap<String, Vec<String>>);
