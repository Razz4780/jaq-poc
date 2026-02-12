use safejaq_types::{EvaluationRequest, EvaluationResult};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tempfile::{NamedTempFile, TempPath};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const EVALUATOR_BINARY: &[u8] =
    include_bytes!(env!("CARGO_BIN_FILE_SAFEJAQ_EVALUATOR_safejaq_evaluator"));

/// Allows for evaluating untrusted JAQ filters with configurable time and memory limits.
pub struct SafeJaq {
    extracted_binary: TempPath,
    time_limit: Duration,
    memory_limit: u64,
}

impl SafeJaq {
    /// Creates a new instance.
    ///
    /// # Params
    ///
    /// * `extraction_dir` - directory where the JAQ evaluator binary will be extracted
    /// * `time_limit` - time limit for evaluating a filter
    /// * `memory_limit` - memory limit for evaluating a filter
    pub fn new(
        extraction_dir: &Path,
        time_limit: Duration,
        memory_limit: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut extracted_binary = NamedTempFile::new_in(extraction_dir)?;
        extracted_binary.write_all(EVALUATOR_BINARY)?;
        extracted_binary.flush()?;
        extracted_binary
            .as_file()
            .set_permissions(Permissions::from_mode(0o755))?;
        let extracted_binary = extracted_binary.into_temp_path();

        Ok(Self {
            extracted_binary,
            time_limit,
            memory_limit,
        })
    }

    /// Evaluates the given JAQ filter against the given payload,
    /// respecting the configured time and memory limits.
    pub async fn evaluate(
        &self,
        filter: String,
        payload: serde_json::Value,
    ) -> Result<bool, SafeJaqError> {
        let mut child = Command::new(&self.extracted_binary)
            .env(
                // The child process will set a memory limit for itself.
                safejaq_types::MEMORY_LIMIT_ENV,
                self.memory_limit.to_string(),
            )
            .env(
                // The child process will set a time limit for itself.
                safejaq_types::TIME_LIMIT_ENV,
                (self.time_limit.as_secs() + 1).to_string(),
            )
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(SafeJaqError::Command)?;

        let request = serde_json::to_string(&EvaluationRequest { filter, payload })
            .expect("serializing simple struct to memory should not fail");

        // Send the evaluation request to the child process
        // and wait for it to finish.
        // Since the time limit passed to the child is counted in seconds,
        // we use our own timeout here.
        let result = tokio::time::timeout(self.time_limit, async {
            child
                .stdin
                .as_mut()
                .expect("was piped")
                .write_all(request.as_bytes())
                .await?;
            child.stdin.as_mut().expect("was piped").shutdown().await?;
            child.wait().await?;
            Ok::<_, std::io::Error>(())
        })
        .await;

        let Ok(Ok(())) = result else {
            // If the child process did not finish in time,
            // or IO on pipes failed, assume it's because the evaluation exceeded the limits.
            // To uncover any potential bugs, wait for the child to finish and log its output,
            // in the background. The child will always eventually finish due to its time limit.
            // We do it in the background because it might take over a second.
            tokio::spawn(async move {
                match child.wait_with_output().await {
                    Ok(output) => {
                        tracing::warn!(
                            status = %output.status,
                            stderr = %String::from_utf8_lossy(&output.stderr),
                            "JAQ evaluator command finished after exceeding limits",
                        );
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "Failed to collect output of JAQ evaluator command after exceeding limits",
                        );
                    }
                }
            });
            return Err(SafeJaqError::LimitExceeded(
                self.time_limit,
                self.memory_limit,
            ));
        };

        let stdout = match child.wait_with_output().await {
            Ok(output) if output.status.success() => output.stdout,
            Ok(output) => {
                tracing::warn!(
                    status = %output.status,
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "JAQ evaluator command failed",
                );
                return Err(SafeJaqError::LimitExceeded(
                    self.time_limit,
                    self.memory_limit,
                ));
            }
            Err(error) => return Err(SafeJaqError::Command(error)),
        };

        match serde_json::from_slice::<EvaluationResult>(&stdout) {
            Ok(result) => result.map_err(SafeJaqError::Evaluation),
            Err(error) => Err(SafeJaqError::Command(std::io::Error::other(format!(
                "command printed malformed output: {error}"
            )))),
        }
    }
}

#[derive(Error, Debug)]
pub enum SafeJaqError {
    #[error("failed to use the evaluator command: {0}")]
    Command(#[source] std::io::Error),
    #[error(
        "filter evaluation exceeded either the time limit of {}ms or the memory limit of {} bytes",
        .0.as_millis(),
        .1,
    )]
    LimitExceeded(Duration, u64),
    #[error("failed to evaluate the filter: {0}")]
    Evaluation(String),
}

#[cfg(test)]
mod tests {
    use crate::{SafeJaq, SafeJaqError};
    use std::time::Duration;

    #[tokio::test]
    async fn test_evaluate() {
        let dir = tempfile::tempdir().unwrap();
        let mut jaq = SafeJaq::new(dir.path(), Duration::from_millis(250), 64 * 1024).unwrap();
        let value = std::iter::repeat('a')
            .take(64 * 1024 * 1024)
            .collect::<String>();
        let error = jaq
            .evaluate(".[]".into(), serde_json::json!({"key": value}))
            .await
            .unwrap_err();
        match error {
            SafeJaqError::LimitExceeded(..) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
