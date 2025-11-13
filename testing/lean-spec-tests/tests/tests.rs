//! Integration tests for leanSpec test vectors
//!
//! These tests load and validate the structure of leanSpec-generated
//! test fixtures. Full execution integration is TODO.

use std::{fs, path::PathBuf};

use lean_spec_tests::{
    fork_choice::{load_fork_choice_test, run_fork_choice_test},
    state_transition::{load_state_transition_test, run_state_transition_test},
};

/// Helper to find all JSON files in a directory recursively
fn find_json_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir);

    if !base_path.exists() {
        eprintln!("Warning: Directory does not exist: {:?}", base_path);
        return files;
    }

    fn visit_dirs(dir: &std::path::Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, files);
                } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    files.push(path);
                }
            }
        }
    }

    visit_dirs(&base_path, &mut files);
    files.sort();
    files
}

#[tokio::test]
async fn test_all_fork_choice_fixtures() {
    let fixtures = find_json_files("fixtures/consensus/fork_choice");

    if fixtures.is_empty() {
        panic!(
            "No fork choice fixtures found! Make sure fixtures are copied to testing/lean-spec-tests/fixtures/"
        );
    }

    println!("Found {} fork choice test fixtures", fixtures.len());

    let mut total_tests = 0;
    let mut passed = 0;
    let mut failed = 0;

    for fixture_path in fixtures {
        println!("\n=== Loading fixture: {:?} ===", fixture_path.file_name());

        match load_fork_choice_test(&fixture_path) {
            Ok(fixture) => {
                for (test_name, test) in &fixture {
                    total_tests += 1;
                    match run_fork_choice_test(test_name, test).await {
                        Ok(_) => {
                            passed += 1;
                        }
                        Err(e) => {
                            failed += 1;
                            eprintln!("FAILED: {} - {:?}", test_name, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to load fixture {:?}: {:?}", fixture_path, e);
                failed += 1;
            }
        }
    }

    println!("\n=== Fork Choice Test Summary ===");
    println!("Total tests: {}", total_tests);
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some fork choice tests failed");
}

#[test]
fn test_all_state_transition_fixtures() {
    let fixtures = find_json_files("fixtures/consensus/state_transition");

    if fixtures.is_empty() {
        panic!(
            "No state transition fixtures found! Make sure fixtures are copied to testing/lean-spec-tests/fixtures/"
        );
    }

    println!("Found {} state transition test fixtures", fixtures.len());

    let mut total_tests = 0;
    let mut passed = 0;
    let mut failed = 0;

    for fixture_path in fixtures {
        println!("\n=== Loading fixture: {:?} ===", fixture_path.file_name());

        match load_state_transition_test(&fixture_path) {
            Ok(fixture) => {
                for (test_name, test) in &fixture {
                    total_tests += 1;
                    match run_state_transition_test(test_name, test) {
                        Ok(_) => {
                            passed += 1;
                        }
                        Err(e) => {
                            failed += 1;
                            eprintln!("FAILED: {} - {:?}", test_name, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to load fixture {:?}: {:?}", fixture_path, e);
                failed += 1;
            }
        }
    }

    println!("\n=== State Transition Test Summary ===");
    println!("Total tests: {}", total_tests);
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some state transition tests failed");
}

#[tokio::test]
async fn test_specific_fork_choice_test() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "fixtures/consensus/fork_choice/devnet/fc/test_fork_choice_head/test_head_with_gaps_in_slots.json",
    );

    let fixture =
        load_fork_choice_test(&fixture_path).expect("Failed to load fork choice test fixture");

    assert!(!fixture.is_empty(), "Fixture should contain tests");

    for (test_name, test) in &fixture {
        println!("\n=== Test: {} ===", test_name);
        run_fork_choice_test(test_name, test)
            .await
            .expect("Test should pass");

        // Validate test structure
        assert_eq!(test.network, "Devnet");
        assert_eq!(test.anchor_state.slot, 0);
        assert_eq!(test.anchor_block.slot, 0);
        assert!(!test.steps.is_empty());
    }
}

#[test]
fn test_specific_state_transition_test() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "fixtures/consensus/state_transition/devnet/state_transition/test_block_processing/test_process_first_block_after_genesis.json",
    );

    let fixture = load_state_transition_test(&fixture_path)
        .expect("Failed to load state transition test fixture");

    assert!(!fixture.is_empty(), "Fixture should contain tests");

    for (test_name, test) in &fixture {
        println!("\n=== Test: {} ===", test_name);
        run_state_transition_test(test_name, test).expect("Test should pass");

        // Validate test structure
        assert_eq!(test.network, "Devnet");
        assert_eq!(test.pre.slot, 0);
        assert!(!test.blocks.is_empty());
    }
}
