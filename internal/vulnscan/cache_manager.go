// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"container/list"
	"crypto/md5"
	"encoding/hex"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// CacheItem 缓存项
type CacheItem struct {
	Key        string
	Value      interface{}
	Expiration time.Time
	CreatedAt  time.Time
	AccessedAt time.Time
	AccessCount int
}

// CacheManager 缓存管理器接口
type CacheManager interface {
	// Get 从缓存中获取值
	Get(key string) (interface{}, bool)
	// Set 向缓存中设置值
	Set(key string, value interface{}, ttl time.Duration)
	// Delete 从缓存中删除值
	Delete(key string)
	// Clear 清空缓存
	Clear()
	// Contains 检查缓存中是否包含某个键
	Contains(key string) bool
	// Size 获取缓存大小
	Size() int
	// Keys 获取所有缓存键
	Keys() []string
	// Cleanup 清理过期项
	Cleanup()
	// StartCleanupRoutine 启动自动清理过期项的协程
	StartCleanupRoutine(interval time.Duration)
	// StopCleanupRoutine 停止自动清理过期项的协程
	StopCleanupRoutine()
	// GetStats 获取缓存统计信息
	GetStats() CacheStats
}

// CacheStats 缓存统计信息
type CacheStats struct {
	Size       int         `json:"size"`
	Hits       int64       `json:"hits"`
	Misses     int64       `json:"misses"`
	HitRate    float64     `json:"hit_rate"`
	Evictions  int64       `json:"evictions"`
	Insertions int64       `json:"insertions"`
	Deletions  int64       `json:"deletions"`
	CleanupRuns int64      `json:"cleanup_runs"`
	ItemsCleaned int64     `json:"items_cleaned"`
	AvgItemSize float64    `json:"avg_item_size"`
	MemoryUsage int64      `json:"memory_usage"`
}

// DefaultCacheManager 默认缓存管理器
type DefaultCacheManager struct {
	items      map[string]*CacheItem
	mutex      sync.RWMutex
	maxSize    int
	stats      CacheStats
	evictionPolicy string // "lru", "fifo", "none"
	lruList    *list.List
	lruIndex   map[string]*list.Element
	cleanupTicker *time.Ticker
	doneChan   chan struct{}
}

// NewDefaultCacheManager 创建默认缓存管理器
func NewDefaultCacheManager(maxSize int, evictionPolicy string) *DefaultCacheManager {
	cm := &DefaultCacheManager{
		items:         make(map[string]*CacheItem),
		maxSize:       maxSize,
		evictionPolicy: evictionPolicy,
		lruList:       list.New(),
		lruIndex:      make(map[string]*list.Element),
		doneChan:      make(chan struct{}),
	}
	return cm
}

// Get 从缓存中获取值
func (cm *DefaultCacheManager) Get(key string) (interface{}, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	item, found := cm.items[key]
	if !found {
		cm.stats.Misses++
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(item.Expiration) {
		cm.mutex.RUnlock()
		cm.Delete(key)
		cm.mutex.RLock()
		cm.stats.Misses++
		return nil, false
	}

	// 更新访问时间和访问计数
	item.AccessedAt = time.Now()
	item.AccessCount++

	// 如果是LRU策略，将访问的项移到列表前面
	if cm.evictionPolicy == "lru" {
		if elem, exists := cm.lruIndex[key]; exists {
			cm.lruList.MoveToFront(elem)
		}
	}

	cm.stats.Hits++
	cm.updateHitRate()
	return item.Value, true
}

// Set 向缓存中设置值
func (cm *DefaultCacheManager) Set(key string, value interface{}, ttl time.Duration) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 如果缓存已满且需要淘汰
	if len(cm.items) >= cm.maxSize && cm.maxSize > 0 {
		cm.evict()
	}

	expiration := time.Now().Add(ttl)
	item := &CacheItem{
		Key:        key,
		Value:      value,
		Expiration: expiration,
		CreatedAt:  time.Now(),
		AccessedAt: time.Now(),
		AccessCount: 1,
	}

	// 如果键已存在，先删除旧项
	if _, exists := cm.items[key]; exists {
		cm.deleteInternal(key)
	}

	cm.items[key] = item
	cm.stats.Insertions++

	// 如果是LRU策略，将新项添加到列表前面
	if cm.evictionPolicy == "lru" {
		elem := cm.lruList.PushFront(key)
		cm.lruIndex[key] = elem
	}
}

// Delete 从缓存中删除值
func (cm *DefaultCacheManager) Delete(key string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.deleteInternal(key)
}

// deleteInternal 内部删除方法（需要加锁）
func (cm *DefaultCacheManager) deleteInternal(key string) {
	if _, exists := cm.items[key]; exists {
		delete(cm.items, key)
		cm.stats.Deletions++

		// 如果是LRU策略，从LRU列表中删除
		if cm.evictionPolicy == "lru" {
			if elem, exists := cm.lruIndex[key]; exists {
				cm.lruList.Remove(elem)
				delete(cm.lruIndex, key)
			}
		}
	}
}

// Clear 清空缓存
func (cm *DefaultCacheManager) Clear() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.items = make(map[string]*CacheItem)
	if cm.evictionPolicy == "lru" {
		cm.lruList.Init()
		cm.lruIndex = make(map[string]*list.Element)
	}
}

// Contains 检查缓存中是否包含某个键
func (cm *DefaultCacheManager) Contains(key string) bool {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	_, found := cm.items[key]
	return found
}

// Size 获取缓存大小
func (cm *DefaultCacheManager) Size() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return len(cm.items)
}

// Keys 获取所有缓存键
func (cm *DefaultCacheManager) Keys() []string {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	keys := make([]string, 0, len(cm.items))
	for k := range cm.items {
		keys = append(keys, k)
	}
	return keys
}

// Cleanup 清理过期项
func (cm *DefaultCacheManager) Cleanup() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()
	keysToDelete := make([]string, 0)

	for key, item := range cm.items {
		if now.After(item.Expiration) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		cm.deleteInternal(key)
	}

	cm.stats.CleanupRuns++
	cm.stats.ItemsCleaned += int64(len(keysToDelete))
	if len(keysToDelete) > 0 {
		log.Debug().Int("count", len(keysToDelete)).Msg("清理过期缓存项")
	}
}

// StartCleanupRoutine 启动自动清理过期项的协程
func (cm *DefaultCacheManager) StartCleanupRoutine(interval time.Duration) {
	if cm.cleanupTicker != nil {
		cm.StopCleanupRoutine()
	}

	cm.cleanupTicker = time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-cm.cleanupTicker.C:
				cm.Cleanup()
			case <-cm.doneChan:
				return
			}
		}
	}()

	log.Debug().Dur("interval", interval).Msg("启动缓存自动清理协程")
}

// StopCleanupRoutine 停止自动清理过期项的协程
func (cm *DefaultCacheManager) StopCleanupRoutine() {
	if cm.cleanupTicker != nil {
		cm.cleanupTicker.Stop()
		cm.cleanupTicker = nil
		close(cm.doneChan)
		cm.doneChan = make(chan struct{})
		log.Debug().Msg("停止缓存自动清理协程")
	}
}

// GetStats 获取缓存统计信息
func (cm *DefaultCacheManager) GetStats() CacheStats {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	// 计算平均项大小
	var totalSize int64
	for _, item := range cm.items {
		// 简单估算内存使用，实际应用中可以使用更精确的方法
		totalSize += int64(len(item.Key) + 16) // 16是估算的Value指针大小
	}

	avgItemSize := 0.0
	if len(cm.items) > 0 {
		avgItemSize = float64(totalSize) / float64(len(cm.items))
	}

	cm.stats.Size = len(cm.items)
	cm.stats.AvgItemSize = avgItemSize
	cm.stats.MemoryUsage = totalSize

	return cm.stats
}

// evict 淘汰缓存项
func (cm *DefaultCacheManager) evict() {
	if cm.evictionPolicy == "lru" {
		// LRU策略：淘汰最近最少使用的项
		if elem := cm.lruList.Back(); elem != nil {
			key := elem.Value.(string)
			cm.deleteInternal(key)
			cm.stats.Evictions++
		}
	} else if cm.evictionPolicy == "fifo" {
		// FIFO策略：淘汰最早添加的项
		for key, item := range cm.items {
			cm.deleteInternal(key)
			cm.stats.Evictions++
			break
		}
	}
}

// updateHitRate 更新命中率
func (cm *DefaultCacheManager) updateHitRate() {
	total := cm.stats.Hits + cm.stats.Misses
	if total > 0 {
		cm.stats.HitRate = float64(cm.stats.Hits) / float64(total)
	}
}

// GenerateCacheKey 生成缓存键
func GenerateCacheKey(url string, method string, headers map[string]string, body string) string {
	// 创建一个包含所有参数的字符串
	keyStr := url + "|" + method
	for k, v := range headers {
		keyStr += "|" + k + ":" + v
	}
	keyStr += "|" + body

	// 使用MD5哈希生成固定长度的键
	hash := md5.Sum([]byte(keyStr))
	return hex.EncodeToString(hash[:])
}

// GenerateResponseCacheKey 生成响应缓存键
func GenerateResponseCacheKey(url string, method string, headers map[string]string, body string, payload string) string {
	// 创建一个包含所有参数的字符串
	keyStr := url + "|" + method
	for k, v := range headers {
		keyStr += "|" + k + ":" + v
	}
	keyStr += "|" + body + "|" + payload

	// 使用MD5哈希生成固定长度的键
	hash := md5.Sum([]byte(keyStr))
	return hex.EncodeToString(hash[:])
}