// Package dedup 提供了基于内容相似度的网页去重功能。
// 其核心思想类似于 Simhash 算法，用于快速判断两个文档的相似性。
package dedup

import (
	"bufio"
	"bytes"
	"crypto/sha1" // 使用更现代的哈希算法
	"encoding/binary"
	"hash"
	"io"
	"math"
	"strings"
	"sync"
	//"unsafe"

	"golang.org/x/net/html"
)

const (
	// defaultVectorDimensions 决定了每个页面特征向量的大小。
	// 向量维度越高，对页面特征的描述越精细，但计算量和存储开销也越大。
	defaultVectorDimensions = 64
	// defaultThreshold is the default similarity threshold for deduplication
	defaultThreshold = 0.95
	// bufferSize for optimized reading
	bufferSize = 8192
	// maxCacheSize limits the number of signatures stored in memory
	maxCacheSize = 10000
)

// PageSignature 代表一个已解析HTML页面的特征向量。
// 向量中的每个元素代表一个特征维度的权重。
type PageSignature []int

// String returns a string representation of the signature for debugging
func (ps PageSignature) String() string {
	var builder strings.Builder
	builder.WriteByte('[')
	for i, val := range ps {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(string(rune(val + '0')))
	}
	builder.WriteByte(']')
	return builder.String()
}

// Hash returns a hash of the signature for efficient comparison
func (ps PageSignature) Hash() uint64 {
	h := sha1.New()
	for _, val := range ps {
		binary.Write(h, binary.BigEndian, int32(val))
	}
	hashBytes := h.Sum(nil)
	return binary.BigEndian.Uint64(hashBytes[:8])
}

// textExtractor 用于高效地从HTML中提取文本内容并生成特征向量。
type textExtractor struct {
	hasher     hash.Hash
	dimensions int
	vector     PageSignature
	textBuffer strings.Builder
}

func newTextExtractor(dimensions int) *textExtractor {
	return &textExtractor{
		hasher:     sha1.New(),
		dimensions: dimensions,
		vector:     make(PageSignature, dimensions),
	}
}

func (te *textExtractor) reset() {
	te.hasher.Reset()
	for i := range te.vector {
		te.vector[i] = 0
	}
	te.textBuffer.Reset()
}

func (te *textExtractor) processText(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	
	// 预处理文本：移除多余空白字符，转换为小写
	text = strings.ToLower(normalizeWhitespace(text))
	
	te.hasher.Reset()
	te.hasher.Write([]byte(text))
	hashBytes := te.hasher.Sum(nil)
	hashInt := binary.BigEndian.Uint64(hashBytes[:8])
	dimension := int(hashInt % uint64(te.dimensions))
	te.vector[dimension]++
}

// normalizeWhitespace replaces multiple whitespace characters with single spaces
func normalizeWhitespace(s string) string {
	var result strings.Builder
	result.Grow(len(s)) // 预分配空间
	
	var prevSpace bool
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				result.WriteByte(' ')
				prevSpace = true
			}
		} else {
			result.WriteRune(r)
			prevSpace = false
		}
	}
	
	return strings.TrimSpace(result.String())
}

// GeneratePageSignature 从一个HTML文档创建一个特征向量（页面签名）。
// 算法步骤:
// 1. 解析HTML，并使用栈进行迭代式（非递归）的DOM遍历。
// 2. 对每个非空文本节点的内容进行预处理（小写转换、去空格）。
// 3. 对处理后的文本计算哈希值。
// 4. 将哈希值映射到向量的一个维度上（通过取模运算）。
// 5. 增加该维度的权重。
// 最终得到的向量就代表了整个页面的文本内容分布特征。
func GeneratePageSignature(body io.Reader, dimensions int) (PageSignature, error) {
	if dimensions <= 0 {
		dimensions = defaultVectorDimensions
	}
	
	// 使用缓冲读取器提高性能
	var reader io.Reader = body
	if _, ok := body.(*bufio.Reader); !ok {
		reader = bufio.NewReaderSize(body, bufferSize)
	}
	
	doc, err := html.Parse(reader)
	if err != nil {
		// 如果是EOF错误，说明body为空，可以返回一个空的签名
		if err == io.EOF {
			return make(PageSignature, dimensions), nil
		}
		return nil, err
	}
	// 如果文档解析结果为空，也返回空签名
	if doc == nil {
		return make(PageSignature, dimensions), nil
	}

	extractor := newTextExtractor(dimensions)
	defer extractor.reset() // 清理资源
	
	// 使用迭代替代递归，避免栈溢出
	stack := make([]*html.Node, 0, 100) // 预分配栈空间
	stack = append(stack, doc)
	
	for len(stack) > 0 {
		// 弹出栈顶元素
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		
		if current.Type == html.TextNode {
			extractor.processText(current.Data)
		}
		
		// 将子节点压入栈中（逆序以保持遍历顺序）
		for child := current.LastChild; child != nil; child = child.PrevSibling {
			stack = append(stack, child)
		}
	}
	
	// 返回副本以避免内存泄漏
	result := make(PageSignature, dimensions)
	copy(result, extractor.vector)
	return result, nil
}

// Similarity 计算两个页面签名之间的余弦相似度。
// 值范围在0到1之间，值越接近1，表示两个页面内容的相似程度越高。
func (ps PageSignature) Similarity(other PageSignature) float64 {
	if len(ps) != len(other) || len(ps) == 0 {
		return 0.0
	}
	
	// 快速检查：如果两个向量都为零向量
	if ps.isZeroVector() || other.isZeroVector() {
		return 0.0
	}
	
	var dotProduct, mag1, mag2 float64
	
	// 向量化计算，提高性能
	for i := 0; i < len(ps); i++ {
		p, o := float64(ps[i]), float64(other[i])
		dotProduct += p * o
		mag1 += p * p
		mag2 += o * o
	}
	
	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}
	
	return dotProduct / (math.Sqrt(mag1) * math.Sqrt(mag2))
}

// isZeroVector checks if the signature is a zero vector
func (ps PageSignature) isZeroVector() bool {
	for _, val := range ps {
		if val != 0 {
			return false
		}
	}
	return true
}

// signatureEntry represents a cached signature with metadata
type signatureEntry struct {
	signature PageSignature
	hash      uint64
	url       string
	timestamp int64 // for LRU eviction
}

// Deduplicator 负责处理基于内容相似度的URL去重。
// 它维护一个已处理页面的签名缓存，并使用哈希索引和LRU策略来优化性能。
type Deduplicator struct {
	mu           sync.RWMutex                    // 使用读写锁提高并发性能
	signatures   map[string]*signatureEntry     // 存储签名条目
	hashIndex    map[uint64][]*signatureEntry   // 哈希索引用于快速查找
	threshold    float64
	maxCacheSize int
	accessCount  int64 // 用于LRU
}

// DeduplicatorOption represents configuration options for Deduplicator
type DeduplicatorOption func(*Deduplicator)

// WithThreshold sets the similarity threshold
func WithThreshold(threshold float64) DeduplicatorOption {
	return func(d *Deduplicator) {
		if threshold > 0 && threshold <= 1.0 {
			d.threshold = threshold
		}
	}
}

// WithMaxCacheSize sets the maximum cache size
func WithMaxCacheSize(size int) DeduplicatorOption {
	return func(d *Deduplicator) {
		if size > 0 {
			d.maxCacheSize = size
		}
	}
}

// NewDeduplicator creates a new Deduplicator with options.
func NewDeduplicator(opts ...DeduplicatorOption) *Deduplicator {
	d := &Deduplicator{
		signatures:   make(map[string]*signatureEntry),
		hashIndex:    make(map[uint64][]*signatureEntry),
		threshold:    defaultThreshold,
		maxCacheSize: maxCacheSize,
	}
	
	// 应用选项
	for _, opt := range opts {
		opt(d)
	}
	
	return d
}

// IsUnique 检查一个URL的内容是否是唯一的。
// 它首先生成页面的签名，然后与缓存中的签名进行比较。
// 如果相似度超过阈值，则认为页面是重复的。
func (d *Deduplicator) IsUnique(url string, body io.Reader) (bool, error) {
	// 首先尝试读锁检查是否已存在
	d.mu.RLock()
	if _, exists := d.signatures[url]; exists {
		d.mu.RUnlock()
		return false, nil // URL already processed
	}
	d.mu.RUnlock()
	
	// 读取body内容
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return false, err
	}
	
	// 生成签名
	currentSig, err := GeneratePageSignature(bytes.NewReader(bodyBytes), defaultVectorDimensions)
	if err != nil {
		return false, err
	}
	
	// 计算签名哈希用于快速查找
	sigHash := currentSig.Hash()
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// 双重检查，防止并发情况下重复处理
	if _, exists := d.signatures[url]; exists {
		return false, nil
	}
	
	// 使用哈希索引进行快速相似性检查
	if candidates, exists := d.hashIndex[sigHash]; exists {
		for _, candidate := range candidates {
			if currentSig.Similarity(candidate.signature) > d.threshold {
				return false, nil // Found a similar page
			}
		}
	}
	
	// 如果没有找到相似页面，进行全量检查（作为后备）
	for _, entry := range d.signatures {
		if entry.hash != sigHash && currentSig.Similarity(entry.signature) > d.threshold {
			return false, nil // Found a similar page
		}
	}
	
	// 检查缓存大小并进行LRU淘汰
	if len(d.signatures) >= d.maxCacheSize {
		d.evictLRU()
	}
	
	// 添加新签名
	d.accessCount++
	entry := &signatureEntry{
		signature: currentSig,
		hash:      sigHash,
		url:       url,
		timestamp: d.accessCount,
	}
	
	d.signatures[url] = entry
	d.hashIndex[sigHash] = append(d.hashIndex[sigHash], entry)
	
	return true, nil
}

// evictLRU removes the least recently used entries
func (d *Deduplicator) evictLRU() {
	if len(d.signatures) < d.maxCacheSize {
		return
	}
	
	// 找到最旧的条目
	var oldestURL string
	var oldestTimestamp int64 = math.MaxInt64
	
	for url, entry := range d.signatures {
		if entry.timestamp < oldestTimestamp {
			oldestTimestamp = entry.timestamp
			oldestURL = url
		}
	}
	
	if oldestURL != "" {
		d.removeEntry(oldestURL)
	}
}

// removeEntry removes an entry from both maps
func (d *Deduplicator) removeEntry(url string) {
	if entry, exists := d.signatures[url]; exists {
		delete(d.signatures, url)
		
		// 从哈希索引中移除
		if candidates, exists := d.hashIndex[entry.hash]; exists {
			for i, candidate := range candidates {
				if candidate.url == url {
					// 移除该元素
					d.hashIndex[entry.hash] = append(candidates[:i], candidates[i+1:]...)
					break
				}
			}
			// 如果该哈希下没有其他条目，删除整个键
			if len(d.hashIndex[entry.hash]) == 0 {
				delete(d.hashIndex, entry.hash)
			}
		}
	}
}

// GetStats returns statistics about the deduplicator
func (d *Deduplicator) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	return map[string]interface{}{
		"total_signatures":    len(d.signatures),
		"hash_buckets":       len(d.hashIndex),
		"threshold":          d.threshold,
		"max_cache_size":     d.maxCacheSize,
		"access_count":       d.accessCount,
	}
}

// Clear removes all stored signatures
func (d *Deduplicator) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.signatures = make(map[string]*signatureEntry)
	d.hashIndex = make(map[uint64][]*signatureEntry)
	d.accessCount = 0
}

// SetThreshold updates the similarity threshold
func (d *Deduplicator) SetThreshold(threshold float64) {
	if threshold > 0 && threshold <= 1.0 {
		d.mu.Lock()
		d.threshold = threshold
		d.mu.Unlock()
	}
}

// GetThreshold returns the current similarity threshold
func (d *Deduplicator) GetThreshold() float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.threshold
}

// Contains checks if a URL is already in the cache
func (d *Deduplicator) Contains(url string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	_, exists := d.signatures[url]
	return exists
}

// Size returns the number of stored signatures
func (d *Deduplicator) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	return len(d.signatures)
}
