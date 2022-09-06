package onvmpoller

import (
	"sync"
)

// ConcurrentMap is a thread safe map collection with better performance.
// The backend map entries are separated into the different partitions.
// Threads can access the different partitions safely without lock.
type ConcurrentMap struct {
	partitions    []*innerMap
	numOfBlockets int
}

// Partitionable is the interface which should be implemented by key type.
// It is to define how to partition the entries.
type Partitionable interface {
	// Value is raw value of the key
	Value() interface{}

	// PartitionKey is used for getting the partition to store the entry with the key.
	// E.g. the key's hash could be used as its PartitionKey
	// The partition for the key is partitions[(PartitionKey % m.numOfBlockets)]
	//
	// 1 Why not provide the default hash function for partition?
	// Ans: As you known, the partition solution would impact the performance significantly.
	// The proper partition solution balances the access to the different partitions and
	// avoid of the hot partition. The access mode highly relates to your business.
	// So, the better partition solution would just be designed according to your business.
	PartitionKey() int64
}

type innerMap struct {
	m    map[interface{}]interface{}
	lock sync.RWMutex
}

/*********************************
	Partitionable interface
*********************************/
func (four_tuple *Four_tuple_rte) Value() interface{} {
	return *four_tuple
}

func (four_tuple *Four_tuple_rte) PartitionKey() int64 {
	return int64((four_tuple.Src_ip * 59) ^ (four_tuple.Dst_ip) ^ (uint32(four_tuple.Src_port) << 16) ^ uint32(four_tuple.Dst_port) ^ uint32(6))
}

func Key(four_tuple Four_tuple_rte) *Four_tuple_rte {
	return &four_tuple
}

/*********************************
	Concurrent Map API
*********************************/
func createInnerMap() *innerMap {
	return &innerMap{
		m: make(map[interface{}]interface{}),
	}
}

func (im *innerMap) get(key Partitionable) (interface{}, bool) {
	keyVal := key.Value()
	im.lock.RLock()
	v, ok := im.m[keyVal]
	im.lock.RUnlock()
	return v, ok
}

func (im *innerMap) set(key Partitionable, v interface{}) {
	keyVal := key.Value()
	im.lock.Lock()
	im.m[keyVal] = v
	im.lock.Unlock()
}

func (im *innerMap) del(key Partitionable) {
	keyVal := key.Value()
	im.lock.Lock()
	delete(im.m, keyVal)
	im.lock.Unlock()
}

func (im *innerMap) get_del(key Partitionable) (interface{}, bool) {
	keyVal := key.Value()
	im.lock.Lock()
	v, ok := im.m[keyVal]
	if ok {
		delete(im.m, keyVal)
	}
	im.lock.Unlock()
	return v, ok
}

// CreateConcurrentMap is to create a ConcurrentMap with the setting number of the partitions
func CreateConcurrentMap(numOfPartitions int) *ConcurrentMap {
	var partitions []*innerMap
	for i := 0; i < numOfPartitions; i++ {
		partitions = append(partitions, createInnerMap())
	}
	return &ConcurrentMap{partitions, numOfPartitions}
}

func (m *ConcurrentMap) getPartition(key Partitionable) *innerMap {
	partitionID := key.PartitionKey() % int64(m.numOfBlockets)
	return (*innerMap)(m.partitions[partitionID])
}

// Get is to get the value by the key
func (m *ConcurrentMap) Get(key Partitionable) (interface{}, bool) {
	return m.getPartition(key).get(key)
}

// Set is to store the KV entry to the map
func (m *ConcurrentMap) Set(key Partitionable, v interface{}) {
	im := m.getPartition(key)
	im.set(key, v)
}

// Del is to delete the entries by the key
func (m *ConcurrentMap) Del(key Partitionable) {
	im := m.getPartition(key)
	im.del(key)
}

// GetAndDel is to first find if the entries exist then delete the entries by the key
func (m *ConcurrentMap) GetAndDel(key Partitionable) (interface{}, bool) {
	return m.getPartition(key).get_del(key)
}
