use clap::Parser;
use packet_eye_agent::{run, Args};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run(args).await
}
