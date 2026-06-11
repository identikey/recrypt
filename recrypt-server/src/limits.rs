//! Process resource limits.

/// Cap the process virtual address space (RLIMIT_AS) at `gb` gibibytes.
///
/// Malformed PRE material can drive OpenFHE/cereal deserialization to attempt
/// an arbitrarily large allocation from an attacker-controlled length field
/// (recrypt-hrq). With a bounded address space the runaway `operator new`
/// fails as `std::bad_alloc` — which the FFI layer catches and surfaces as an
/// error — instead of the allocator satisfying it and the host OOM-killing the
/// proxy.
///
/// `gb == 0` disables the cap. RLIMIT_AS is enforced on Linux; macOS largely
/// ignores it, so this is a best-effort safeguard there and a container/cgroup
/// memory limit should back it in production. The soft limit is only ever
/// lowered, never raised above the inherited hard limit.
pub fn apply_address_space_limit(gb: u64) {
    if gb == 0 {
        tracing::warn!(
            "address-space limit disabled (limits.address_space_gb = 0); \
             malformed PRE input could drive unbounded allocations"
        );
        return;
    }

    let bytes = gb.saturating_mul(1024 * 1024 * 1024);

    #[cfg(unix)]
    {
        // SAFETY: `get`/`setrlimit` are called with a valid resource id and a
        // fully-initialized `rlimit`; we read the current limits before writing.
        unsafe {
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_AS, &mut rl) != 0 {
                tracing::warn!("getrlimit(RLIMIT_AS) failed; address-space limit not applied");
                return;
            }

            let desired = bytes as libc::rlim_t;
            // Never exceed the inherited hard limit.
            rl.rlim_cur = if rl.rlim_max != libc::RLIM_INFINITY && desired > rl.rlim_max {
                rl.rlim_max
            } else {
                desired
            };

            if libc::setrlimit(libc::RLIMIT_AS, &rl) != 0 {
                tracing::warn!("setrlimit(RLIMIT_AS) failed; address-space limit not applied");
            } else {
                tracing::info!("address-space limit set to {gb} GiB (RLIMIT_AS)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = bytes;
        tracing::warn!("address-space limit unsupported on this platform; skipping");
    }
}
