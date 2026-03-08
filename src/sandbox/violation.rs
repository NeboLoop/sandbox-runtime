use std::sync::{Arc, Mutex};

use crate::utils::command::encode_sandboxed_command;

/// A sandbox violation event.
#[derive(Debug, Clone)]
pub struct SandboxViolationEvent {
    pub line: String,
    pub command: Option<String>,
    pub encoded_command: Option<String>,
    pub timestamp: std::time::SystemTime,
}

/// In-memory tail for sandbox violations.
#[derive(Clone)]
pub struct SandboxViolationStore {
    inner: Arc<Mutex<StoreInner>>,
}

#[allow(clippy::type_complexity)]
struct StoreInner {
    violations: Vec<SandboxViolationEvent>,
    total_count: usize,
    max_size: usize,
    listeners: Vec<Option<Box<dyn Fn(&[SandboxViolationEvent]) + Send>>>,
    next_listener_id: usize,
}

impl SandboxViolationStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                violations: Vec::new(),
                total_count: 0,
                max_size: 100,
                listeners: Vec::new(),
                next_listener_id: 0,
            })),
        }
    }

    pub fn add_violation(&self, violation: SandboxViolationEvent) {
        let mut inner = self.inner.lock().unwrap();
        inner.violations.push(violation);
        inner.total_count += 1;
        if inner.violations.len() > inner.max_size {
            let len = inner.violations.len();
            inner.violations = inner.violations[len - inner.max_size..].to_vec();
        }
        let violations = inner.violations.clone();
        for listener in inner.listeners.iter().flatten() {
            listener(&violations);
        }
    }

    pub fn get_violations(&self, limit: Option<usize>) -> Vec<SandboxViolationEvent> {
        let inner = self.inner.lock().unwrap();
        match limit {
            Some(n) => {
                let len = inner.violations.len();
                if n >= len {
                    inner.violations.clone()
                } else {
                    inner.violations[len - n..].to_vec()
                }
            }
            None => inner.violations.clone(),
        }
    }

    pub fn get_count(&self) -> usize {
        self.inner.lock().unwrap().violations.len()
    }

    pub fn get_total_count(&self) -> usize {
        self.inner.lock().unwrap().total_count
    }

    pub fn get_violations_for_command(&self, command: &str) -> Vec<SandboxViolationEvent> {
        let command_base64 = encode_sandboxed_command(command);
        let inner = self.inner.lock().unwrap();
        inner
            .violations
            .iter()
            .filter(|v| v.encoded_command.as_deref() == Some(&command_base64))
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.violations.clear();
        // Don't reset total_count
        let violations = inner.violations.clone();
        for listener in inner.listeners.iter().flatten() {
            listener(&violations);
        }
    }

    /// Subscribe to violation events. Returns an unsubscribe handle.
    /// Call `unsubscribe(id)` with the returned id to remove the listener.
    pub fn subscribe<F>(&self, listener: F) -> usize
    where
        F: Fn(&[SandboxViolationEvent]) + Send + 'static,
    {
        let mut inner = self.inner.lock().unwrap();
        let violations = inner.violations.clone();
        listener(&violations);
        let id = inner.next_listener_id;
        inner.next_listener_id += 1;
        // Ensure vec is large enough
        while inner.listeners.len() <= id {
            inner.listeners.push(None);
        }
        inner.listeners[id] = Some(Box::new(listener));
        id
    }

    /// Remove a listener by its subscription id.
    pub fn unsubscribe(&self, id: usize) {
        let mut inner = self.inner.lock().unwrap();
        if id < inner.listeners.len() {
            inner.listeners[id] = None;
        }
    }
}

impl Default for SandboxViolationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_violations() {
        let store = SandboxViolationStore::new();
        store.add_violation(SandboxViolationEvent {
            line: "test violation".to_string(),
            command: Some("echo hello".to_string()),
            encoded_command: None,
            timestamp: std::time::SystemTime::now(),
        });
        assert_eq!(store.get_count(), 1);
        assert_eq!(store.get_total_count(), 1);
    }

    #[test]
    fn test_max_size() {
        let store = SandboxViolationStore::new();
        for i in 0..150 {
            store.add_violation(SandboxViolationEvent {
                line: format!("violation {i}"),
                command: None,
                encoded_command: None,
                timestamp: std::time::SystemTime::now(),
            });
        }
        assert_eq!(store.get_count(), 100);
        assert_eq!(store.get_total_count(), 150);
    }

    #[test]
    fn test_clear_preserves_total_count() {
        let store = SandboxViolationStore::new();
        for _ in 0..5 {
            store.add_violation(SandboxViolationEvent {
                line: "test".to_string(),
                command: None,
                encoded_command: None,
                timestamp: std::time::SystemTime::now(),
            });
        }
        store.clear();
        assert_eq!(store.get_count(), 0);
        assert_eq!(store.get_total_count(), 5);
    }
}
