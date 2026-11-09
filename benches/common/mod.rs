//! Inputs and settings shared by the benchmark targets.

use std::time::Duration;

use criterion::measurement::WallTime;
use criterion::{AxisScale, BenchmarkGroup, BenchmarkId, Criterion, PlotConfiguration, Throughput};

/// The input sizes of every size group: 1 MiB, 10 MiB and 100 MiB (104.9 MB).
pub const SIZES: [usize; 3] = [1 << 20, 10 << 20, 100 << 20];

/// A fixed key and IV. Benchmarks never protect real data, so a constant key and a
/// reused IV are acceptable here and nowhere else.
pub const KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
pub const IV: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

/// Returns `len` bytes of deterministic test data. The content does not affect
/// the timing.
pub fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// Starts a group whose benchmarks run at each of [`SIZES`].
///
/// Uses ten samples, Criterion's minimum, because a single run takes seconds at the
/// largest size. The sampling mode stays automatic, so Criterion samples short
/// runs linearly and switches to flat sampling for long ones. The summary charts
/// use a log scale because the sizes span two orders of magnitude.
pub fn size_group<'a>(c: &'a mut Criterion, name: &str) -> BenchmarkGroup<'a, WallTime> {
    let mut group = c.benchmark_group(name);
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    group
}

/// Sets the group's throughput to `size` bytes and returns the size as a label,
/// such as `10MiB`.
///
/// The summary charts place each point by its throughput in bytes, so the label is
/// only what the report shows.
pub fn set_size(group: &mut BenchmarkGroup<'_, WallTime>, size: usize) -> String {
    group.throughput(Throughput::Bytes(size as u64));
    format!("{}MiB", size >> 20)
}

/// Returns the id of `function` at the size `label`.
pub fn id(function: &str, label: &str) -> BenchmarkId {
    BenchmarkId::new(function, label)
}
