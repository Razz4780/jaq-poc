use serde::{Deserialize, Serialize};

/// Request to evaluate a JAQ filter against a payload.
#[derive(Deserialize, Serialize)]
pub struct EvaluationRequest {
    pub filter: String,
    pub payload: serde_json::Value,
}

/// Result of evaluating a JAQ filter against a payload.
pub type EvaluationResult = Result<bool, String>;

/// Name of environment variable used to set the memory limit for the evaluator subprocess.
pub const MEMORY_LIMIT_ENV: &str = "SAFEJAQ_EVALUATOR_MEM_LIMIT";
/// Name of environment variable used to set the time limit for the evaluator subprocess (in seconds).
pub const TIME_LIMIT_ENV: &str = "SAFEJAQ_EVALUATOR_TIME_LIMIT";
