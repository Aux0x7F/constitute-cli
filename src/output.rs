use anyhow::Result;
use serde::Serialize;

pub fn print_value<T: Serialize>(
    json_output: bool,
    value: &T,
    human: impl FnOnce() -> String,
) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{}", human());
    }
    Ok(())
}

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
