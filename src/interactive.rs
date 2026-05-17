use anyhow::Result;
use rustyline::DefaultEditor;

pub fn run() -> Result<()> {
    println!("constitute interactive shell");
    println!("Type 'help' for commands, 'exit' to quit.");
    let mut rl = DefaultEditor::new()?;
    loop {
        let line = rl.readline("constitute> ");
        match line {
            Ok(input) => {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);
                match trimmed {
                    "exit" | "quit" => break,
                    "help" => {
                        println!(
                            "Available now: service, capability, channel, diagnostics, protocol, auth, config, doctor"
                        );
                        println!(
                            "Navigate services as: constitute service [location] <service> [node] [field=value]"
                        );
                        println!(
                            "Navigate swarm directories as: constitute capability <name>; constitute channel list --capability <name>"
                        );
                        println!(
                            "Raw frames and CAAC/Nostr tooling live under: constitute protocol ..."
                        );
                    }
                    other => {
                        println!(
                            "Interactive dispatch is intentionally thin in v1. Run: constitute {other}"
                        );
                    }
                }
            }
            Err(_) => break,
        }
    }
    Ok(())
}
