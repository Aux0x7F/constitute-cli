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
                            "Available now: auth, gateway, service, projection, diagnostics, protocol, doctor"
                        );
                        println!("Run non-interactive commands as: constitute <subcommand> ...");
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
