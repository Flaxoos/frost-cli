use clap::{command, Parser, Subcommand};
#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    StartSession {
        #[arg(short, long)]
        participant_index: u32,
    },
}

#[derive(Parser)]
#[command(author, version, about = "Interactive session commands")]
pub enum InteractiveCommands {
    /// Sign a message (assumes threshold participants are ready)
    Sign,
    /// Display available commands
    Help,
    /// Exit the session
    Exit,
}