// === CONFIGURATION CONSTANTS ===
// Configuration values for the WASM signer worker

/// Change this constant and recompile to adjust logging verbosity
/// Available levels: Error, Warn, Info, Debug, Trace
pub const CURRENT_LOG_LEVEL: log::Level = log::Level::Info;

/// Maximum session duration in milliseconds (30 minutes)
pub const SESSION_MAX_DURATION_MS: f64 = 30.0 * 60.0 * 1000.0;
