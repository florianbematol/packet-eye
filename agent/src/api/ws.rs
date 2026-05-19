//! WebSocket endpoint that streams enriched packet batches, periodic
//! stats ticks, and alerts to the frontend.
//!
//! Wire format: text JSON messages, one per Message payload.
//! Three kinds of messages:
//!     {"type":"packets","data":[...]}    array of EnrichedPacket
//!     {"type":"stats","data":{...}}      single StatsTick
//!     {"type":"alerts","data":[...]}     array of Alert

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;

use crate::alerts::Alert;
use crate::enrich::EnrichedPacket;
use crate::state::{AppState, StatsTick};

#[derive(Serialize)]
#[serde(tag = "type", content = "data", rename_all = "lowercase")]
enum Outgoing<'a> {
    Packets(&'a Vec<EnrichedPacket>),
    Stats(StatsTick),
    Alerts(&'a Vec<Alert>),
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut packet_rx = state.tx.subscribe();
    let mut alert_rx = state.alert_tx.subscribe();
    let mut stats_tick = tokio::time::interval(Duration::from_millis(1000));

    // Send an initial stats snapshot so the UI has numbers right away.
    if let Ok(json) = serde_json::to_string(&Outgoing::Stats(state.current_stats())) {
        if socket.send(Message::Text(json)).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            // Live packet batch
            res = packet_rx.recv() => match res {
                Ok(batch) => {
                    let payload = serde_json::to_string(&Outgoing::Packets(&batch));
                    if let Ok(json) = payload {
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::debug!("ws client lagged on packets, dropped {n} batches");
                    continue;
                }
                Err(RecvError::Closed) => break,
            },

            // Live alerts
            res = alert_rx.recv() => match res {
                Ok(alerts) => {
                    let payload = serde_json::to_string(&Outgoing::Alerts(&alerts));
                    if let Ok(json) = payload {
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::debug!("ws client lagged on alerts, dropped {n} batches");
                    continue;
                }
                Err(RecvError::Closed) => break,
            },

            // Periodic stats
            _ = stats_tick.tick() => {
                let tick = state.current_stats();
                if let Ok(json) = serde_json::to_string(&Outgoing::Stats(tick)) {
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            },

            // Allow client-initiated close
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    tracing::debug!("ws recv error: {e}");
                    break;
                }
            },
        }
    }
}
