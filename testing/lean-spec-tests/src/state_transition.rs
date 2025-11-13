//! State transition test runner for leanSpec test vectors

use std::path::Path;

use anyhow::{Context, Result};

use crate::types::{StateTransitionTest, TestFixture};

/// Load a state transition test fixture from a JSON file
pub fn load_state_transition_test(
    path: impl AsRef<Path>,
) -> Result<TestFixture<StateTransitionTest>> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read test file: {:?}", path.as_ref()))?;

    let fixture: TestFixture<StateTransitionTest> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse test file: {:?}", path.as_ref()))?;

    Ok(fixture)
}

/// Run a single state transition test case
pub fn run_state_transition_test(test_name: &str, test: &StateTransitionTest) -> Result<()> {
    println!("Running state transition test: {}", test_name);

    // TODO: Convert leanSpec types to ream types
    // TODO: Process blocks through state transition
    // TODO: Validate post-state or expected exception

    // For now, just validate the test structure
    println!("  Network: {}", test.network);
    println!("  Pre-state slot: {}", test.pre.slot);
    println!("  Number of blocks: {}", test.blocks.len());
    println!(
        "  Expected result: {}",
        if test.expect_exception.is_some() {
            format!("Exception: {}", test.expect_exception.as_ref().unwrap())
        } else {
            "Success".to_string()
        }
    );

    if let Some(post) = &test.post {
        println!("  Post-state checks:");
        if let Some(slot) = post.slot {
            println!("    - slot: {}", slot);
        }
        if let Some(count) = post.historical_block_hashes_count {
            println!("    - historical_block_hashes_count: {}", count);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_state_transition_fixture() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/consensus/state_transition/devnet/state_transition/test_block_processing/test_process_first_block_after_genesis.json"
        );

        let fixture = load_state_transition_test(fixture_path)
            .expect("Failed to load state transition test fixture");

        assert!(
            !fixture.is_empty(),
            "Fixture should contain at least one test"
        );

        // Run each test in the fixture
        for (test_name, test) in &fixture {
            run_state_transition_test(test_name, test).expect("State transition test should pass");
        }
    }
}
