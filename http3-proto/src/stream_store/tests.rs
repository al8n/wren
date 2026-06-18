use super::*;
use crate::event::StreamId;

#[test]
fn insert_lookup_remove_reuse_and_capacity() {
  let mut store: ArrayStore<'_, u32, 2> = ArrayStore::new();
  let a = StreamId::new(0);
  let b = StreamId::new(4);
  let c = StreamId::new(8);

  assert!(store.insert(a, 100).is_ok());
  assert!(store.insert(b, 200).is_ok());
  // At capacity (2 slots): a third insert returns the value back as Err.
  assert_eq!(store.insert(c, 300).unwrap_err(), 300);

  assert_eq!(store.get(a), Some(&100));
  assert_eq!(store.get_mut(b).copied(), Some(200));
  assert_eq!(store.get(c), None);

  // Remove frees the slot for reuse.
  assert_eq!(store.remove(a), Some(100));
  assert_eq!(store.get(a), None);
  assert!(store.insert(c, 300).is_ok()); // reuses a's slot
  assert_eq!(store.get(c), Some(&300));

  // iter_mut visits the live entries.
  let mut seen: std::vec::Vec<(u64, u32)> = std::vec::Vec::new();
  for (id, v) in store.iter_mut() {
    seen.push((id.get(), *v));
  }
  seen.sort_unstable();
  assert_eq!(seen, std::vec![(4, 200), (8, 300)]);
}

#[test]
fn caller_slice_backed_store_works() {
  let mut slots = [ArraySlot::EMPTY; 3];
  let mut store = ArrayStore::<u8, 0>::with_slots(&mut slots[..]);
  assert!(store.insert(StreamId::new(1), 7).is_ok());
  assert_eq!(store.get(StreamId::new(1)), Some(&7));
}
