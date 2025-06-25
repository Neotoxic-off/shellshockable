pub const TIMEOUT_SECS: u64 = 5;
pub const SHELLSHOCK_HEADER: &str = "() { :; }; echo; echo; /bin/bash -c 'echo shellshocked'";
pub const WAVE_SIZE: usize = 10;
