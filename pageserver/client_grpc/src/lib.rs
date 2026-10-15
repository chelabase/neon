// This crate is a tonic client: its errors are `tonic::Status` (176 bytes), returned by value as
// tonic's own API does.
#![allow(clippy::result_large_err)]

mod client;
mod pool;
mod retry;

pub use client::{PageserverClient, ShardSpec};
