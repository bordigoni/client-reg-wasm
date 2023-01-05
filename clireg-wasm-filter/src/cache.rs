pub mod hard_coded;
pub mod shared;

pub trait ReadableCache<K, V>
where
    K: Clone,
    V: Clone,
{
    fn get(&self, key: &K) -> Option<V>;
}

// this is unsafe, but need to revamp
// the whole cache abstraction and use channel to update values
pub trait WritableCache<K, V>: Sync + Send {
    fn put(&mut self, key: K, value: Option<V>);
    fn delete(&mut self, key: K);
}
