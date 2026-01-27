use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Simple rate limiter that tracks requests per IP address
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Tracks request count and window start time per IP
    state: Arc<RwLock<HashMap<IpAddr, (u32, Instant)>>>,
    /// Maximum requests allowed per window
    max_requests: u32,
    /// Time window duration
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified requests per minute
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_requests: max_requests_per_minute,
            window: Duration::from_secs(60),
        }
    }

    /// Create from environment variables with defaults
    pub fn from_env() -> Self {
        let max_requests = std::env::var("RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0); // Default: disabled

        Self::new(max_requests)
    }

    /// Check if the given IP is within rate limits
    /// Returns true if request should be allowed, false if rate limited
    pub async fn check(&self, ip: IpAddr) -> bool {
        if self.max_requests == 0 {
            return true;
        }

        let mut state = self.state.write().await;
        let now = Instant::now();

        // Global limiter: ignore per-IP and aggregate counts.
        let key = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let entry = state.entry(key).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) > self.window {
            entry.0 = 0;
            entry.1 = now;
        }

        // Check limit
        if entry.0 >= self.max_requests {
            tracing::warn!("Rate limit exceeded for IP: {}", ip);
            return false; // Rate limited
        }

        entry.0 += 1;
        true
    }

    /// Clean up old entries to prevent memory growth
    pub async fn cleanup(&self) {
        let mut state = self.state.write().await;
        let now = Instant::now();
        let before_count = state.len();

        state.retain(|_, (_, start)| now.duration_since(*start) < self.window);

        let removed = before_count - state.len();
        if removed > 0 {
            tracing::debug!("Rate limiter cleanup: removed {} expired entries", removed);
        }
    }

    /// Get current statistics for monitoring
    pub async fn stats(&self) -> (usize, u32) {
        let state = self.state.read().await;
        (state.len(), self.max_requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rate_limiter_disabled_allows() {
        let limiter = RateLimiter::new(0);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..10 {
            assert!(limiter.check(ip).await, "Disabled limiter should allow");
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit_global() {
        let limiter = RateLimiter::new(3);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Use up the global limit across different IPs
        assert!(limiter.check(ip1).await);
        assert!(limiter.check(ip2).await);
        assert!(limiter.check(ip1).await);

        // Should be blocked regardless of IP
        assert!(
            !limiter.check(ip2).await,
            "Should block once global limit is reached"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_resets_after_window() {
        let limiter = RateLimiter {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_requests: 3,
            window: Duration::from_millis(100), // 100ms window for testing
        };
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Use up the limit
        for _ in 0..3 {
            limiter.check(ip).await;
        }

        // Should be blocked
        assert!(!limiter.check(ip).await);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should allow again
        assert!(limiter.check(ip).await, "Should allow after window reset");
    }

    #[tokio::test]
    async fn test_cleanup() {
        let limiter = RateLimiter {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_requests: 5,
            window: Duration::from_millis(50),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Make a request
        limiter.check(ip).await;

        // Should have 1 entry
        let (count, _) = limiter.stats().await;
        assert_eq!(count, 1);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cleanup
        limiter.cleanup().await;

        // Should have 0 entries
        let (count, _) = limiter.stats().await;
        assert_eq!(count, 0);
    }
}
