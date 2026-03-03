#[cfg(all(feature = "devnet3", feature = "devnet4"))]
compile_error!(
    "Features 'devnet3' and 'devnet4' are mutually exclusive. Use --no-default-features --features devnet4 to build for devnet4."
);

#[cfg(not(any(feature = "devnet3", feature = "devnet4")))]
compile_error!("Either 'devnet3' or 'devnet4' feature must be enabled.");
pub mod attestation;
pub mod block;
pub mod checkpoint;
pub mod config;
pub mod slot;
pub mod state;
pub mod utils;
pub mod validator;
