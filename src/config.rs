use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddrV4;

use anyhow::Context;

#[derive(Debug)]
pub(crate) struct Endpoint {
    pub(crate) addr: SocketAddrV4,
    pub(crate) cmd: Vec<String>,
}

// Split string on whitespace, respecting single and double
// quote-enclosed content. No escape characters are supported.
fn split_cmd(cmd: &str) -> anyhow::Result<Vec<String>> {
    let mut chars = cmd.chars().enumerate();

    let mut cmd = Vec::new();
    let mut curr = String::new();
    let mut has_curr = false;

    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() {
            if has_curr {
                cmd.push(curr);
                curr = String::new();
                has_curr = false;
            }
        } else if c == '"' || c == '\'' {
            loop {
                let Some((_, d)) = chars.next() else {
                    anyhow::bail!("unterminated string at position {}", i)
                };

                if c == d { break } else { curr.push(d) }
            }
            has_curr = true;
        } else {
            curr.push(c);
            has_curr = true;
        }
    }

    if has_curr {
        cmd.push(curr);
    }

    Ok(cmd)
}

// Read simple configuration format from path
pub(crate) fn read_config(path: &str) -> anyhow::Result<Vec<Endpoint>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);

    let mut endpoint: Option<Endpoint> = None;
    let mut endpoints = Vec::new();

    let mut read_config_line = |line: String| {
        match line.chars().next() {
            None | Some('#') => (),
            Some(' ' | '\t') => {
                if let Some(e) = &mut endpoint {
                    e.cmd.extend(split_cmd(&line)?);
                } else {
                    anyhow::bail!("continuation line has no predecessor")
                };
            }
            Some(_) => {
                if let Some(e) = endpoint.take() {
                    endpoints.push(e)
                }

                let Some((addr_str, cmd_str)) = line.split_once([' ', '\t'])
                else {
                    anyhow::bail!("config line has addr but no space");
                };

                endpoint = Some(Endpoint {
                    addr: addr_str.parse()?,
                    cmd: split_cmd(cmd_str)?,
                });
            }
        }

        Ok(())
    };

    for (i, line) in reader.lines().enumerate() {
        read_config_line(line?)
            .with_context(|| format!("config error on line {}", i + 1))?;
    }

    if let Some(e) = endpoint {
        endpoints.push(e)
    }

    Ok(endpoints)
}
