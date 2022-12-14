pub mod hard_coded;

pub trait ReadableCache<K, V>
where
    K: Clone,
    V: Clone,
{
    fn get(&self, key: &K) -> Option<V>;
}

pub trait WritableCache<K, V> {
    fn put(&mut self, key: K, value: Option<V>);
    fn _delete(&self, key: K);
}
