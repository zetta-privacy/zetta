//! Cuckoo hash table keyed by (address, j), storing the leaf index.

use crate::server::oprf::{ServerKey, positions};

const MAX_EVICTIONS: usize = 500;

/// One entry: (address[20], deposit_ordinal j, leaf_index).
pub type Entry = ([u8; 20], u32, u64);

pub struct CuckooTable {
    pub table: Vec<Option<Entry>>,
    pub key: ServerKey,
}

impl CuckooTable {
    /// Build from (address, j) -> leaf_index entries.
    /// `size` is the table size (>= 1.3 * entries.len()).
    pub fn build(entries: &[Entry], key: ServerKey, size: usize) -> Self {
        let mut t = Self {
            table: vec![None; size],
            key,
        };
        for e in entries {
            t.insert(*e);
        }
        t
    }

    fn key_bytes(&self, e: &Entry) -> Vec<u8> {
        let mut x = Vec::with_capacity(24);
        x.extend_from_slice(&e.0);
        x.extend_from_slice(&e.1.to_be_bytes());
        x
    }

    fn hashes(&self, e: &Entry) -> (usize, usize) {
        let prf = self.key.prf(&self.key_bytes(e));
        positions(&prf, self.table.len())
    }

    fn insert(&mut self, e: Entry) {
        let mut curr = e;
        let mut try_second = false;
        for _ in 0..MAX_EVICTIONS {
            let (h1, h2) = self.hashes(&curr);
            let pos = if try_second { h2 } else { h1 };
            if self.table[pos].is_none() {
                self.table[pos] = Some(curr);
                return;
            }
            let evicted = self.table[pos].take().unwrap();
            self.table[pos] = Some(curr);
            // move evicted to its OTHER slot
            let (eh1, _) = self.hashes(&evicted);
            curr = evicted;
            try_second = pos == eh1; // if evicted from h1, try h2; else h1
        }
        panic!("cuckoo eviction loop — enlarge the table");
    }

    /// Look up the two candidate slots for a client-side (address, j).
    pub fn lookup(&self, address: &[u8; 20], j: u32) -> [&Option<Entry>; 2] {
        let e = (*address, j, 0);
        let (h1, h2) = self.hashes(&e);
        [&self.table[h1], &self.table[h2]]
    }
}
