use std::path::Path;

use anyhow::{Context, Result};

use crate::types::{TestFixture, state_transition::StateTransitionTest};

/// Load a state transition test fixture from a JSON file
pub fn load_state_transition_test(
    path: impl AsRef<Path>,
) -> Result<TestFixture<StateTransitionTest>> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read test file: {:?}", path.as_ref().display()))?;

    let fixture: TestFixture<StateTransitionTest> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse test file: {:?}", path.as_ref().display()))?;

    Ok(fixture)
}

/// Run a single state transition test case
pub fn run_state_transition_test(test_name: &str, test: &StateTransitionTest) -> Result<()> {
    println!("Running state transition test: {test_name}");

    // TODO: Convert leanSpec types to ream types
    // TODO: Process blocks through state transition
    // TODO: Validate post-state or expected exception

    // For now, just print the network
    println!("Network: {}", test.network);

    Ok(())
}
