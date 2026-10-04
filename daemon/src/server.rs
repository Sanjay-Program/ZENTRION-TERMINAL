use crate::{ExecRequest, ExecResult, Metrics};
use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub async fn start_daemon(port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    // Accept exactly ONE connection
    let (mut stream, _) = listener.accept().await?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read a line of text (the JSON request)
    reader.read_line(&mut line).await?;

    if line.trim().is_empty() {
        return Ok(());
    }

    // Attempt to parse the request, though we might not strictly need to for this minimal example
    let _req: ExecRequest = serde_json::from_str(&line)?;

    let result = ExecResult {
        status: "allowed".to_string(),
        request_id: "req-mock-id".to_string(),
        metrics: Metrics {
            cpu_usage: 1.5,
            memory_usage: 1024,
        },
    };

    let response = serde_json::to_string(&result)?;
    writer.write_all(response.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    Ok(())
}
