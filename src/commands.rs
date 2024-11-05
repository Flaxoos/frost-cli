use crate::config::get_shares;
use clap::{command, value_parser, Parser, Subcommand};
#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    // CreateParticipant,
    StartSession {
        #[arg(
            short, 
            long, 
            value_parser = value_parser!(u32).range(1..=get_shares() as i64),
            help = "The participant index must be between 1 and 5 (inclusive)"
        )]
        participant_index: u32,
    },
}

#[derive(Parser)]
#[command(author, version, about = "Interactive session commands")]
pub enum InteractiveCommands {
    /// Sign a message (assumes threshold participants are ready)
    Sign,
    /// Display available commands
    // Help,
    /// Exit the session
    Exit,
}
