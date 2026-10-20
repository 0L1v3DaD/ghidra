/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package generic.cache;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Generic cache implementation that removes items from the cache when they are no longer
 * referenced. It uses weak references for the values and a small hard cache
 * so that recent items don't get garbage collected immediately.
 * <P>
 * This class is thread safe.
 * 
 * @param <K> The type of the key stored in this cache
 * @param <V> The type of the value stored in this cache
 */
public class WeakReferenceCache<K, V> {

	private final ConcurrentHashMap<K, KeyedReference<K, V>> refsById;
	private final ReferenceQueue<V> refQueue;
	private volatile HardRing<V> hardRing;

	/**
	 * Constructs a new WeakReferenceCache with a given hard cache size.  The hard cache size is
	 * the minimum number of objects to keep in the cache. Typically, the cache will contain
	 * more than this number, but the excess objects are subject to garbage collection.
	 * @param hardCacheSize the minimum number of objects to keep in the cache.
	 */
	public WeakReferenceCache(int hardCacheSize) {
		if (hardCacheSize <= 0) {
			throw new IllegalArgumentException("Hard cache size must be at least 1");
		}
		refsById = new ConcurrentHashMap<>();
		refQueue = new ReferenceQueue<>();
		hardRing = new HardRing<>(hardCacheSize);
	}

	/**
	 * Retrieves the database object with the given key from the cache.
	 * @param key the key of the object to retrieve.
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public V get(K key) {
		if (key == null) {
			return null;
		}
		KeyedReference<K, V> ref = refsById.get(key);
		if (ref == null) {
			return null;
		}
		V v = ref.get();
		if (v == null) {
			refsById.remove(key, ref);
			return null;
		}
		hardRing.recordAccess(ref, v);
		return v;
	}

	/**
	 * Returns the number of objects currently in the cache.
	 * @return the number of objects currently in the cache.
	 */
	public int size() {
		return refsById.size();
	}

	/**
	 * Sets the number of objects to protect against garbage collection.
	 * @param size the minimum number of objects to keep in the cache.
	 */
	public synchronized void setHardCacheSize(int size) {
		if (size <= 0) {
			throw new IllegalArgumentException("Hard cache size must be at least 1");
		}
		hardRing = new HardRing<>(size);
	}

	/**
	 * Adds the given database object to the cache.
	 * @param key the key for the cached object
	 * @param data the object to add to the cache
	 * @return the object that has been added to the cache
	 */
	public synchronized V add(K key, V data) {
		processQueue();
		if (key == null || data == null) {
			return data;
		}
		KeyedReference<K, V> ref = new KeyedReference<>(key, data, refQueue);
		hardRing.pinNew(ref, data);
		KeyedReference<K, V> oldRef = refsById.put(key, ref);
		if (oldRef != null && oldRef != ref) {
			V oldVal = oldRef.get();
			if (oldVal != null && oldVal != data) {
				hardRing.unpin(oldRef, oldVal);
			}
			oldRef.clear();
		}
		return data;
	}

	/**
	 * Returns an List of all the cached objects.
	 * @return an List of all the cached objects.
	 */
	public List<V> getCachedObjects() {
		List<V> list = new ArrayList<>();
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v != null) {
				list.add(v);
			}
		}
		return list;
	}

	/**
	 * Applies the given consumer to all values in the cache.
	 * @param consumer the consumer to apply to all values in the cache
	 */
	public void apply(Consumer<V> consumer) {
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v != null) {
				consumer.accept(v);
			}
		}
	}

	/**
	 * Removes the object with the given key from the cache.
	 * @param key the key of the object to remove
	 * @return the value that was removed from the cache
	 */
	public synchronized V delete(K key) {
		processQueue();
		if (key == null) {
			return null;
		}
		KeyedReference<K, V> ref = refsById.remove(key);
		V v = null;
		if (ref != null) {
			v = ref.get();
			if (v != null) {
				hardRing.unpin(ref, v);
			}
			ref.clear();
		}
		return v;
	}

	public synchronized void deleteIf(Predicate<V> predicate) {
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v == null || predicate.test(v)) {
				if (refsById.remove(ref.getKey(), ref)) {
					if (v != null) {
						hardRing.unpin(ref, v);
					}
					ref.clear();
				}
			}
		}
	}

	// we know the cast is safe--we put them in there
	@SuppressWarnings("unchecked")
	private void processQueue() {
		KeyedReference<K, V> ref;
		while ((ref = (KeyedReference<K, V>) refQueue.poll()) != null) {
			K key = ref.getKey();
			refsById.remove(key, ref);
		}
	}

	private static final class HardRing<V> {
		private final AtomicReferenceArray<V> ring;
		private final int capacity;
		private final AtomicInteger cursor = new AtomicInteger();

		HardRing(int capacity) {
			this.capacity = capacity;
			this.ring = new AtomicReferenceArray<>(capacity);
		}

		void pinNew(KeyedReference<?, V> ref, V v) {
			if (ref.slot == -2) {
				return;
			}
			int nextSlot = Integer.remainderUnsigned(cursor.getAndIncrement(), capacity);
			ring.lazySet(nextSlot, v);
			ref.slot = nextSlot;
			if (ref.deleted) {
				ring.compareAndSet(nextSlot, v, null);
			}
		}

		void recordAccess(KeyedReference<?, V> ref, V v) {
			if (ref.deleted) {
				return;
			}
			int oldSlot = ref.slot;
			if (oldSlot >= 0 && oldSlot < capacity && ring.get(oldSlot) == v) {
				return;
			}
			pinNew(ref, v);
		}

		void unpin(KeyedReference<?, V> ref, V v) {
			ref.deleted = true;
			int slot = ref.slot;
			ref.slot = -2;
			if (slot >= 0 && slot < capacity) {
				ring.compareAndSet(slot, v, null);
			}
		}
	}

	private static class KeyedReference<K, V> extends WeakReference<V> {
		private final K key;
		volatile int slot = -1;
		volatile boolean deleted = false;

		KeyedReference(K key, V obj, ReferenceQueue<V> queue) {
			super(obj, queue);
			this.key = key;
		}

		K getKey() {
			return key;
		}
	}

}
