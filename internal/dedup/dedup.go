// Package dedup 提供了基于内容相似度的网页去重功能。
// 其核心思想类似于 Simhash 算法，用于快速判断两个文档的相似性。
package dedup

import (
	"bufio"
	"context"
	"crypto/sha256" // 使用更安全的哈希算法
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

const (
	// defaultVectorDimensions 决定了每个页面特征向量的大小。
	defaultVectorDimensions = 128 // 增加维度提高精度
	// defaultThreshold 默认相似度阈值
	defaultThreshold = 0.85
	// bufferSize 优化读取的缓冲区大小
	bufferSize = 16384
	// maxCacheSize 内存中存储的签名数量限制
	maxCacheSize = 50000
	// cleanupInterval 清理过期条目的间隔
	cleanupInterval = 5 * time.Minute
	// maxAge 条目的最大存活时间
	maxAge = 24 * time.Hour
	// batchSize 批处理大小
	batchSize = 1000
	// minTextLength 最小文本长度阈值
	minTextLength = 10
)

// PageSignature 代表一个已解析HTML页面的特征向量。
type PageSignature struct {
	Vector     []float64 `json:"vector"`     // 使用float64提高精度
	Dimensions int       `json:"dimensions"` // 维度信息
	Hash       uint64    `json:"hash"`       // 签名哈希
	Metadata   *SignatureMetadata `json:"metadata,omitempty"`
}

// SignatureMetadata 签名元数据
type SignatureMetadata struct {
	URL           string            `json:"url"`
	Title         string            `json:"title"`
	ContentLength int               `json:"content_length"`
	Language      string            `json:"language"`
	Keywords      []string          `json:"keywords"`
	CreatedAt     time.Time         `json:"created_at"`
	LastAccessed  time.Time         `json:"last_accessed"`
	AccessCount   int64             `json:"access_count"`
	Tags          map[string]string `json:"tags"`
}

// NewPageSignature 创建新的页面签名
func NewPageSignature(dimensions int) *PageSignature {
	if dimensions <= 0 {
		dimensions = defaultVectorDimensions
	}
	return &PageSignature{
		Vector:     make([]float64, dimensions),
		Dimensions: dimensions,
		Metadata:   &SignatureMetadata{
			CreatedAt:    time.Now(),
			LastAccessed: time.Now(),
			Tags:         make(map[string]string),
		},
	}
}

// String 返回签名的字符串表示
func (ps *PageSignature) String() string {
	if ps == nil {
		return "nil"
	}
	return fmt.Sprintf("PageSignature{Hash:%x, Dimensions:%d, Vector:[%.3f...]}", 
		ps.Hash, ps.Dimensions, ps.Vector[0])
}

// IsZero 检查是否为零向量
func (ps *PageSignature) IsZero() bool {
	if ps == nil || len(ps.Vector) == 0 {
		return true
	}
	
	for _, val := range ps.Vector {
		if val != 0 {
			return false
		}
	}
	return true
}

// Normalize 标准化向量
func (ps *PageSignature) Normalize() {
	if ps == nil || len(ps.Vector) == 0 {
		return
	}
	
	var magnitude float64
	for _, val := range ps.Vector {
		magnitude += val * val
	}
	
	if magnitude == 0 {
		return
	}
	
	magnitude = math.Sqrt(magnitude)
	for i := range ps.Vector {
		ps.Vector[i] /= magnitude
	}
}

// ComputeHash 计算签名哈希
func (ps *PageSignature) ComputeHash() {
	if ps == nil {
		return
	}
	
	h := sha256.New()
	for _, val := range ps.Vector {
		binary.Write(h, binary.BigEndian, val)
	}
	hashBytes := h.Sum(nil)
	ps.Hash = binary.BigEndian.Uint64(hashBytes[:8])
}

// Similarity 计算两个页面签名之间的余弦相似度
func (ps *PageSignature) Similarity(other *PageSignature) float64 {
	if ps == nil || other == nil {
		return 0.0
	}
	
	if len(ps.Vector) != len(other.Vector) || len(ps.Vector) == 0 {
		return 0.0
	}
	
	// 快速检查：如果两个向量都为零向量
	if ps.IsZero() || other.IsZero() {
		return 0.0
	}
	
	var dotProduct, mag1, mag2 float64
	
	// 向量化计算，提高性能
	for i := 0; i < len(ps.Vector); i++ {
		p, o := ps.Vector[i], other.Vector[i]
		dotProduct += p * o
		mag1 += p * p
		mag2 += o * o
	}
	
	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}
	
	return dotProduct / (math.Sqrt(mag1) * math.Sqrt(mag2))
}

// JaccardSimilarity 计算Jaccard相似度（补充相似度算法）
func (ps *PageSignature) JaccardSimilarity(other *PageSignature) float64 {
	if ps == nil || other == nil || len(ps.Vector) != len(other.Vector) {
		return 0.0
	}
	
	var intersection, union float64
	
	for i := 0; i < len(ps.Vector); i++ {
		a, b := ps.Vector[i], other.Vector[i]
		intersection += math.Min(a, b)
		union += math.Max(a, b)
	}
	
	if union == 0 {
		return 0.0
	}
	
	return intersection / union
}

// TextExtractor 用于高效地从HTML中提取文本内容并生成特征向量
type TextExtractor struct {
	hasher       hash.Hash
	dimensions   int
	signature    *PageSignature
	textBuffer   strings.Builder
	wordCount    map[string]int
	totalWords   int
	features     []string
	stopWords    map[string]bool
	minWordLen   int
	maxWordLen   int
}

// NewTextExtractor 创建新的文本提取器
func NewTextExtractor(dimensions int) *TextExtractor {
	if dimensions <= 0 {
		dimensions = defaultVectorDimensions
	}
	
	return &TextExtractor{
		hasher:     sha256.New(),
		dimensions: dimensions,
		signature:  NewPageSignature(dimensions),
		wordCount:  make(map[string]int),
		features:   make([]string, 0, 100),
		stopWords:  getStopWords(),
		minWordLen: 2,
		maxWordLen: 50,
	}
}

// getStopWords 获取停用词列表
func getStopWords() map[string]bool {
	stopWords := []string{
		"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by",
		"is", "are", "was", "were", "be", "been", "have", "has", "had", "do", "does", "did",
		"will", "would", "could", "should", "may", "might", "can", "must", "shall",
		"i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us", "them",
		"my", "your", "his", "her", "its", "our", "their", "this", "that", "these", "those",
	}
	
	stopWordMap := make(map[string]bool, len(stopWords))
	for _, word := range stopWords {
		stopWordMap[word] = true
	}
	
	return stopWordMap
}

// Reset 重置提取器状态
func (te *TextExtractor) Reset() {
	te.hasher.Reset()
	te.signature = NewPageSignature(te.dimensions)
	te.textBuffer.Reset()
	
	// 重用map以减少内存分配
	for k := range te.wordCount {
		delete(te.wordCount, k)
	}
	
	te.totalWords = 0
	te.features = te.features[:0]
}

// ProcessText 处理文本内容
func (te *TextExtractor) ProcessText(text string) {
	text = strings.TrimSpace(text)
	if len(text) < minTextLength {
		return
	}
	
	// 预处理文本
	text = te.preprocessText(text)
	
	// 分词并统计
	words := te.tokenize(text)
	for _, word := range words {
		if te.isValidWord(word) {
			te.wordCount[word]++
			te.totalWords++
		}
	}
}

// preprocessText 预处理文本
func (te *TextExtractor) preprocessText(text string) string {
	// 转换为小写
	text = strings.ToLower(text)
	
	// 标准化空白字符
	text = normalizeWhitespace(text)
	
	// 移除特殊字符，保留字母、数字和空格
	var result strings.Builder
	result.Grow(len(text))
	
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == ' ' {
			result.WriteRune(r)
		} else if r >= 0x4e00 && r <= 0x9fff { // 中文字符
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// tokenize 分词
func (te *TextExtractor) tokenize(text string) []string {
	// 简单的空格分词，可以根据需要替换为更复杂的分词器
	words := strings.Fields(text)
	
	// 对于中文，可以按字符分割
	var result []string
	for _, word := range words {
		if te.containsChinese(word) {
			// 中文按字符分割
			for _, char := range word {
				if char >= 0x4e00 && char <= 0x9fff {
					result = append(result, string(char))
				}
			}
		} else {
			result = append(result, word)
		}
	}
	
	return result
}

// containsChinese 检查是否包含中文字符
func (te *TextExtractor) containsChinese(text string) bool {
	for _, r := range text {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}

// isValidWord 检查单词是否有效
func (te *TextExtractor) isValidWord(word string) bool {
	if len(word) < te.minWordLen || len(word) > te.maxWordLen {
		return false
	}
	
	// 检查是否为停用词
	if te.stopWords[word] {
		return false
	}
	
	// 检查是否全为数字
	if isAllDigits(word) {
		return false
	}
	
	return true
}

// isAllDigits 检查字符串是否全为数字
func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// GenerateSignature 生成最终签名
func (te *TextExtractor) GenerateSignature() *PageSignature {
	if te.totalWords == 0 {
		return te.signature
	}
	
	// 计算TF-IDF权重（简化版本）
	for word, count := range te.wordCount {
		tf := float64(count) / float64(te.totalWords)
		
		// 简化的IDF计算（实际应用中需要语料库统计）
		idf := math.Log(1000.0 / (1.0 + float64(count)))
		
		weight := tf * idf
		
		// 将权重映射到向量维度
		te.hasher.Reset()
		te.hasher.Write([]byte(word))
		hashBytes := te.hasher.Sum(nil)
		hashInt := binary.BigEndian.Uint64(hashBytes[:8])
		dimension := int(hashInt % uint64(te.dimensions))
		
		te.signature.Vector[dimension] += weight
	}
	
	// 标准化向量
	te.signature.Normalize()
	
	// 计算哈希
	te.signature.ComputeHash()
	
	return te.signature
}

// normalizeWhitespace 标准化空白字符
func normalizeWhitespace(s string) string {
	var result strings.Builder
	result.Grow(len(s))
	
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

// HTMLParser HTML解析器
type HTMLParser struct {
	extractTitle    bool
	extractMeta     bool
	extractKeywords bool
	skipTags        map[string]bool
}

// NewHTMLParser 创建HTML解析器
func NewHTMLParser() *HTMLParser {
	skipTags := map[string]bool{
		"script": true,
		"style":  true,
		"noscript": true,
		"iframe": true,
		"object": true,
		"embed":  true,
	}
	
	return &HTMLParser{
		extractTitle:    true,
		extractMeta:     true,
		extractKeywords: true,
		skipTags:        skipTags,
	}
}

// ParseHTML 解析HTML并提取内容
func (hp *HTMLParser) ParseHTML(reader io.Reader, extractor *TextExtractor) error {
	// 使用缓冲读取器提高性能
	var bufferedReader io.Reader = reader
	if _, ok := reader.(*bufio.Reader); !ok {
		bufferedReader = bufio.NewReaderSize(reader, bufferSize)
	}
	
	doc, err := html.Parse(bufferedReader)
	if err != nil {
		if err == io.EOF {
			return nil // 空文档
		}
		return fmt.Errorf("解析HTML失败: %w", err)
	}
	
	if doc == nil {
		return nil
	}
	
	// 使用迭代替代递归，避免栈溢出
	stack := make([]*html.Node, 0, 200)
	stack = append(stack, doc)
	
	for len(stack) > 0 {
		// 弹出栈顶元素
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		
		// 跳过不需要的标签
		if current.Type == html.ElementNode && hp.skipTags[current.Data] {
			continue
		}
		
		// 处理文本节点
		if current.Type == html.TextNode {
			extractor.ProcessText(current.Data)
		}
		
		// 提取元数据
		if current.Type == html.ElementNode {
			hp.extractMetadata(current, extractor.signature.Metadata)
		}
		
		// 将子节点压入栈中（逆序以保持遍历顺序）
		for child := current.LastChild; child != nil; child = child.PrevSibling {
			stack = append(stack, child)
		}
	}
	
	return nil
}

// extractMetadata 提取元数据
func (hp *HTMLParser) extractMetadata(node *html.Node, metadata *SignatureMetadata) {
	if !hp.extractMeta || metadata == nil {
		return
	}
	
	switch node.Data {
	case "title":
		if hp.extractTitle && node.FirstChild != nil {
			metadata.Title = strings.TrimSpace(node.FirstChild.Data)
		}
	case "meta":
		hp.extractMetaTags(node, metadata)
	}
}

// extractMetaTags 提取meta标签信息
func (hp *HTMLParser) extractMetaTags(node *html.Node, metadata *SignatureMetadata) {
	var name, content string
	
	for _, attr := range node.Attr {
		switch attr.Key {
		case "name", "property":
			name = attr.Val
		case "content":
			content = attr.Val
		}
	}
	
	if name == "" || content == "" {
		return
	}
	
	switch strings.ToLower(name) {
	case "description":
		metadata.Tags["description"] = content
	case "keywords":
		if hp.extractKeywords {
			keywords := strings.Split(content, ",")
			for i, keyword := range keywords {
				keywords[i] = strings.TrimSpace(keyword)
			}
			metadata.Keywords = keywords
		}
	case "language", "lang":
		metadata.Language = content
	case "author":
		metadata.Tags["author"] = content
	default:
		if strings.HasPrefix(name, "og:") || strings.HasPrefix(name, "twitter:") {
			metadata.Tags[name] = content
		}
	}
}

// GeneratePageSignature 从HTML文档创建页面签名
func GeneratePageSignature(body io.Reader, dimensions int) (*PageSignature, error) {
	if dimensions <= 0 {
		dimensions = defaultVectorDimensions
	}
	
	extractor := NewTextExtractor(dimensions)
	parser := NewHTMLParser()
	
	if err := parser.ParseHTML(body, extractor); err != nil {
		return nil, fmt.Errorf("生成页面签名失败: %w", err)
	}
	
	signature := extractor.GenerateSignature()
	signature.Metadata.ContentLength = extractor.totalWords
	
	return signature, nil
}

// SignatureCache 签名缓存条目
type SignatureCache struct {
	signature    *PageSignature
	lastAccessed int64
	accessCount  int64
}

// Deduplicator 基于内容相似度的URL去重器
type Deduplicator struct {
	mu            sync.RWMutex
	signatures    map[string]*SignatureCache
	hashIndex     map[uint64][]*SignatureCache
	threshold     float64
	maxCacheSize  int
	dimensions    int
	accessCounter int64
	stats         *DeduplicatorStats
	
	// 配置选项
	enablePersistence bool
	persistencePath   string
	cleanupTicker     *time.Ticker
	ctx               context.Context
	cancel            context.CancelFunc
}

// DeduplicatorStats 去重器统计信息
type DeduplicatorStats struct {
	mu                sync.RWMutex
	TotalChecks       int64     `json:"total_checks"`
	DuplicateFound    int64     `json:"duplicate_found"`
	UniquePages       int64     `json:"unique_pages"`
	CacheHits         int64     `json:"cache_hits"`
	CacheMisses       int64     `json:"cache_misses"`
	CacheEvictions    int64     `json:"cache_evictions"`
	AverageSimilarity float64   `json:"average_similarity"`
	StartTime         time.Time `json:"start_time"`
	LastCleanup       time.Time `json:"last_cleanup"`
}

// DeduplicatorOption 去重器配置选项
type DeduplicatorOption func(*Deduplicator)

// WithThreshold 设置相似度阈值
func WithThreshold(threshold float64) DeduplicatorOption {
	return func(d *Deduplicator) {
		if threshold > 0 && threshold <= 1.0 {
			d.threshold = threshold
		}
	}
}

// WithMaxCacheSize 设置最大缓存大小
func WithMaxCacheSize(size int) DeduplicatorOption {
	return func(d *Deduplicator) {
		if size > 0 {
			d.maxCacheSize = size
		}
	}
}

// WithDimensions 设置向量维度
func WithDimensions(dimensions int) DeduplicatorOption {
	return func(d *Deduplicator) {
		if dimensions > 0 {
			d.dimensions = dimensions
		}
	}
}

// WithPersistence 启用持久化
func WithPersistence(path string) DeduplicatorOption {
	return func(d *Deduplicator) {
		d.enablePersistence = true
		d.persistencePath = path
	}
}

// NewDeduplicator 创建新的去重器
func NewDeduplicator(options ...DeduplicatorOption) *Deduplicator {
	ctx, cancel := context.WithCancel(context.Background())
	
	d := &Deduplicator{
		signatures:   make(map[string]*SignatureCache),
		hashIndex:    make(map[uint64][]*SignatureCache),
		threshold:    defaultThreshold,
		maxCacheSize: maxCacheSize,
		dimensions:   defaultVectorDimensions,
		stats: &DeduplicatorStats{
			StartTime: time.Now(),
		},
		ctx:    ctx,
		cancel: cancel,
	}
	
	// 应用配置选项
	for _, option := range options {
		option(d)
	}
	
	// 启动清理协程
	d.startCleanupRoutine()
	
	// 加载持久化数据
	if d.enablePersistence {
		d.loadFromDisk()
	}
	
	return d
}

// startCleanupRoutine 启动清理协程
func (d *Deduplicator) startCleanupRoutine() {
	d.cleanupTicker = time.NewTicker(cleanupInterval)
	
	go func() {
		defer d.cleanupTicker.Stop()
		
		for {
			select {
			case <-d.cleanupTicker.C:
				d.cleanup()
			case <-d.ctx.Done():
				return
			}
		}
	}()
}

// cleanup 清理过期条目
func (d *Deduplicator) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	now := time.Now().Unix()
	maxAge := int64(maxAge.Seconds())
	
	var toDelete []string
	
	for url, cache := range d.signatures {
		if now-cache.lastAccessed > maxAge {
			toDelete = append(toDelete, url)
		}
	}
	
	for _, url := range toDelete {
		d.removeSignatureUnsafe(url)
	}
	
	// 如果缓存仍然过大，执行LRU清理
	if len(d.signatures) > d.maxCacheSize {
		d.evictLRU(len(d.signatures) - d.maxCacheSize)
	}
	
	d.stats.mu.Lock()
	d.stats.LastCleanup = time.Now()
	d.stats.CacheEvictions += int64(len(toDelete))
	d.stats.mu.Unlock()
}

// evictLRU 执行LRU清理
func (d *Deduplicator) evictLRU(count int) {
	type cacheItem struct {
		url          string
		lastAccessed int64
	}
	
	items := make([]cacheItem, 0, len(d.signatures))
	for url, cache := range d.signatures {
		items = append(items, cacheItem{
			url:          url,
			lastAccessed: cache.lastAccessed,
		})
	}
	
	// 按访问时间排序
	sort.Slice(items, func(i, j int) bool {
		return items[i].lastAccessed < items[j].lastAccessed
	})
	
	// 删除最旧的条目
	for i := 0; i < count && i < len(items); i++ {
		d.removeSignatureUnsafe(items[i].url)
	}
}

// removeSignatureUnsafe 删除签名（不加锁）
func (d *Deduplicator) removeSignatureUnsafe(url string) {
	cache, exists := d.signatures[url]
	if !exists {
		return
	}
	
	// 从哈希索引中删除
	hash := cache.signature.Hash
	if entries, exists := d.hashIndex[hash]; exists {
		for i, entry := range entries {
			if entry == cache {
				d.hashIndex[hash] = append(entries[:i], entries[i+1:]...)
				break
			}
		}
		
		// 如果哈希索引为空，删除整个条目
		if len(d.hashIndex[hash]) == 0 {
			delete(d.hashIndex, hash)
		}
	}
	
	delete(d.signatures, url)
}

// IsDuplicate 检查URL是否为重复内容
func (d *Deduplicator) IsDuplicate(url string, body io.Reader) (bool, string, float64, error) {
	// 生成页面签名
	signature, err := GeneratePageSignature(body, d.dimensions)
	if err != nil {
		return false, "", 0, fmt.Errorf("生成页面签名失败: %w", err)
	}
	
	// 更新统计
	atomic.AddInt64(&d.stats.TotalChecks, 1)
	
	// 检查是否为重复
	isDup, originalURL, similarity := d.checkDuplicate(url, signature)
	
	if isDup {
		atomic.AddInt64(&d.stats.DuplicateFound, 1)
	} else {
		atomic.AddInt64(&d.stats.UniquePages, 1)
		d.addSignature(url, signature)
	}
	
	return isDup, originalURL, similarity, nil
}

// checkDuplicate 检查重复
func (d *Deduplicator) checkDuplicate(url string, signature *PageSignature) (bool, string, float64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	// 首先检查精确哈希匹配
	if entries, exists := d.hashIndex[signature.Hash]; exists {
		for _, entry := range entries {
			if entry.signature.Hash == signature.Hash {
				// 更新访问信息
				atomic.AddInt64(&entry.accessCount, 1)
				entry.lastAccessed = time.Now().Unix()
				atomic.AddInt64(&d.stats.CacheHits, 1)
				
				// 计算精确相似度
				similarity := signature.Similarity(entry.signature)
				if similarity >= d.threshold {
					return true, d.findURLByCache(entry), similarity
				}
			}
		}
	}
	
	// 如果没有精确匹配，进行模糊匹配
	var maxSimilarity float64
	var bestMatchURL string
	
	for candidateURL, cache := range d.signatures {
		similarity := signature.Similarity(cache.signature)
		
		if similarity > maxSimilarity {
			maxSimilarity = similarity
			bestMatchURL = candidateURL
		}
		
		if similarity >= d.threshold {
			// 更新访问信息
			atomic.AddInt64(&cache.accessCount, 1)
			cache.lastAccessed = time.Now().Unix()
			atomic.AddInt64(&d.stats.CacheHits, 1)
			
			return true, candidateURL, similarity
		}
	}
	
	atomic.AddInt64(&d.stats.CacheMisses, 1)
	return false, "", maxSimilarity
}

// findURLByCache 通过缓存找到URL
func (d *Deduplicator) findURLByCache(target *SignatureCache) string {
	for url, cache := range d.signatures {
		if cache == target {
			return url
		}
	}
	return ""
}

// addSignature 添加签名
func (d *Deduplicator) addSignature(url string, signature *PageSignature) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	now := time.Now().Unix()
	cache := &SignatureCache{
		signature:    signature,
		lastAccessed: now,
		accessCount:  1,
	}
	
	// 添加到主缓存
	d.signatures[url] = cache
	
	// 添加到哈希索引
	if d.hashIndex[signature.Hash] == nil {
		d.hashIndex[signature.Hash] = make([]*SignatureCache, 0, 1)
	}
	d.hashIndex[signature.Hash] = append(d.hashIndex[signature.Hash], cache)
	
	// 更新元数据
	if signature.Metadata != nil {
		signature.Metadata.URL = url
		signature.Metadata.LastAccessed = time.Unix(now, 0)
	}
	
		// 检查缓存大小
		if len(d.signatures) > d.maxCacheSize {
			d.evictLRU(len(d.signatures) - d.maxCacheSize)
		}
		
		// 异步持久化
		if d.enablePersistence {
			go d.persistSignature(url, signature)
		}
	}
	
	// BatchIsDuplicate 批量检查重复
	func (d *Deduplicator) BatchIsDuplicate(urls []string, bodies []io.Reader) ([]DuplicateResult, error) {
		if len(urls) != len(bodies) {
			return nil, fmt.Errorf("URLs和bodies数量不匹配")
		}
		
		results := make([]DuplicateResult, len(urls))
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 10) // 限制并发数
		
		for i, url := range urls {
			wg.Add(1)
			go func(index int, u string, body io.Reader) {
				defer wg.Done()
				
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				
				isDup, originalURL, similarity, err := d.IsDuplicate(u, body)
				results[index] = DuplicateResult{
					URL:         u,
					IsDuplicate: isDup,
					OriginalURL: originalURL,
					Similarity:  similarity,
					Error:       err,
				}
			}(i, url, bodies[i])
		}
		
		wg.Wait()
		return results, nil
	}
	
	// DuplicateResult 重复检查结果
	type DuplicateResult struct {
		URL         string  `json:"url"`
		IsDuplicate bool    `json:"is_duplicate"`
		OriginalURL string  `json:"original_url,omitempty"`
		Similarity  float64 `json:"similarity"`
		Error       error   `json:"error,omitempty"`
	}
	
	// GetSimilarPages 获取相似页面
	func (d *Deduplicator) GetSimilarPages(url string, body io.Reader, minSimilarity float64) ([]SimilarPage, error) {
		signature, err := GeneratePageSignature(body, d.dimensions)
		if err != nil {
			return nil, fmt.Errorf("生成页面签名失败: %w", err)
		}
		
		d.mu.RLock()
		defer d.mu.RUnlock()
		
		var similarPages []SimilarPage
		
		for candidateURL, cache := range d.signatures {
			if candidateURL == url {
				continue
			}
			
			similarity := signature.Similarity(cache.signature)
			if similarity >= minSimilarity {
				similarPages = append(similarPages, SimilarPage{
					URL:        candidateURL,
					Similarity: similarity,
					Metadata:   cache.signature.Metadata,
				})
			}
		}
		
		// 按相似度降序排序
		sort.Slice(similarPages, func(i, j int) bool {
			return similarPages[i].Similarity > similarPages[j].Similarity
		})
		
		return similarPages, nil
	}
	
	// SimilarPage 相似页面信息
	type SimilarPage struct {
		URL        string             `json:"url"`
		Similarity float64            `json:"similarity"`
		Metadata   *SignatureMetadata `json:"metadata,omitempty"`
	}
	
	// GetStats 获取统计信息
	func (d *Deduplicator) GetStats() *DeduplicatorStats {
		d.stats.mu.RLock()
		defer d.stats.mu.RUnlock()
		
		// 返回副本
		stats := &DeduplicatorStats{
			TotalChecks:       d.stats.TotalChecks,
			DuplicateFound:    d.stats.DuplicateFound,
			UniquePages:       d.stats.UniquePages,
			CacheHits:         d.stats.CacheHits,
			CacheMisses:       d.stats.CacheMisses,
			CacheEvictions:    d.stats.CacheEvictions,
			AverageSimilarity: d.stats.AverageSimilarity,
			StartTime:         d.stats.StartTime,
			LastCleanup:       d.stats.LastCleanup,
		}
		
		return stats
	}
	
	// GetCacheInfo 获取缓存信息
	func (d *Deduplicator) GetCacheInfo() map[string]interface{} {
		d.mu.RLock()
		defer d.mu.RUnlock()
		
		info := map[string]interface{}{
			"cache_size":      len(d.signatures),
			"max_cache_size":  d.maxCacheSize,
			"hash_index_size": len(d.hashIndex),
			"threshold":       d.threshold,
			"dimensions":      d.dimensions,
			"uptime":         time.Since(d.stats.StartTime).String(),
		}
		
		// 计算缓存使用率
		if d.maxCacheSize > 0 {
			info["cache_usage_rate"] = float64(len(d.signatures)) / float64(d.maxCacheSize)
		}
		
		// 统计哈希冲突
		var totalCollisions int
		for _, entries := range d.hashIndex {
			if len(entries) > 1 {
				totalCollisions += len(entries) - 1
			}
		}
		info["hash_collisions"] = totalCollisions
		
		return info
	}
	
	// RemoveSignature 删除指定URL的签名
	func (d *Deduplicator) RemoveSignature(url string) bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		
		if _, exists := d.signatures[url]; exists {
			d.removeSignatureUnsafe(url)
			return true
		}
		
		return false
	}
	
	// Clear 清空所有缓存
	func (d *Deduplicator) Clear() {
		d.mu.Lock()
		defer d.mu.Unlock()
		
		d.signatures = make(map[string]*SignatureCache)
		d.hashIndex = make(map[uint64][]*SignatureCache)
		
		// 重置统计信息
		d.stats.mu.Lock()
		d.stats.TotalChecks = 0
		d.stats.DuplicateFound = 0
		d.stats.UniquePages = 0
		d.stats.CacheHits = 0
		d.stats.CacheMisses = 0
		d.stats.CacheEvictions = 0
		d.stats.StartTime = time.Now()
		d.stats.mu.Unlock()
	}
	
	// UpdateThreshold 更新相似度阈值
	func (d *Deduplicator) UpdateThreshold(threshold float64) error {
		if threshold <= 0 || threshold > 1.0 {
			return fmt.Errorf("阈值必须在(0,1]范围内")
		}
		
		d.mu.Lock()
		d.threshold = threshold
		d.mu.Unlock()
		
		return nil
	}
	
	// ExportSignatures 导出签名数据
	func (d *Deduplicator) ExportSignatures() (map[string]*PageSignature, error) {
		d.mu.RLock()
		defer d.mu.RUnlock()
		
		exported := make(map[string]*PageSignature, len(d.signatures))
		for url, cache := range d.signatures {
			// 创建副本
			signature := &PageSignature{
				Vector:     make([]float64, len(cache.signature.Vector)),
				Dimensions: cache.signature.Dimensions,
				Hash:       cache.signature.Hash,
			}
			copy(signature.Vector, cache.signature.Vector)
			
			// 复制元数据
			if cache.signature.Metadata != nil {
				signature.Metadata = &SignatureMetadata{
					URL:           cache.signature.Metadata.URL,
					Title:         cache.signature.Metadata.Title,
					ContentLength: cache.signature.Metadata.ContentLength,
					Language:      cache.signature.Metadata.Language,
					Keywords:      make([]string, len(cache.signature.Metadata.Keywords)),
					CreatedAt:     cache.signature.Metadata.CreatedAt,
					LastAccessed:  cache.signature.Metadata.LastAccessed,
					AccessCount:   cache.signature.Metadata.AccessCount,
					Tags:          make(map[string]string),
				}
				copy(signature.Metadata.Keywords, cache.signature.Metadata.Keywords)
				for k, v := range cache.signature.Metadata.Tags {
					signature.Metadata.Tags[k] = v
				}
			}
			
			exported[url] = signature
		}
		
		return exported, nil
	}
	
	// ImportSignatures 导入签名数据
	func (d *Deduplicator) ImportSignatures(signatures map[string]*PageSignature) error {
		d.mu.Lock()
		defer d.mu.Unlock()
		
		for url, signature := range signatures {
			if signature == nil {
				continue
			}
			
			cache := &SignatureCache{
				signature:    signature,
				lastAccessed: time.Now().Unix(),
				accessCount:  1,
			}
			
			d.signatures[url] = cache
			
			// 添加到哈希索引
			if d.hashIndex[signature.Hash] == nil {
				d.hashIndex[signature.Hash] = make([]*SignatureCache, 0, 1)
			}
			d.hashIndex[signature.Hash] = append(d.hashIndex[signature.Hash], cache)
		}
		
		return nil
	}
	
	// 持久化相关方法
	
	// persistSignature 持久化单个签名
	func (d *Deduplicator) persistSignature(url string, signature *PageSignature) {
		if !d.enablePersistence || d.persistencePath == "" {
			return
		}
		
		// 这里可以实现具体的持久化逻辑，比如写入数据库或文件
		// 为了简化，这里只是一个占位符
	}
	
	// loadFromDisk 从磁盘加载数据
	func (d *Deduplicator) loadFromDisk() error {
		if !d.enablePersistence || d.persistencePath == "" {
			return nil
		}
		
		file, err := os.Open(d.persistencePath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // 文件不存在，跳过加载
			}
			return fmt.Errorf("打开持久化文件失败: %w", err)
		}
		defer file.Close()
		
		var signatures map[string]*PageSignature
		decoder := json.NewDecoder(file)
		
		if err := decoder.Decode(&signatures); err != nil {
			return fmt.Errorf("解码持久化数据失败: %w", err)
		}
		
		return d.ImportSignatures(signatures)
	}
	
	// saveToDisk 保存数据到磁盘
	func (d *Deduplicator) saveToDisk() error {
		if !d.enablePersistence || d.persistencePath == "" {
			return nil
		}
		
		signatures, err := d.ExportSignatures()
		if err != nil {
			return fmt.Errorf("导出签名失败: %w", err)
		}
		
		file, err := os.Create(d.persistencePath)
		if err != nil {
			return fmt.Errorf("创建持久化文件失败: %w", err)
		}
		defer file.Close()
		
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		
		if err := encoder.Encode(signatures); err != nil {
			return fmt.Errorf("编码持久化数据失败: %w", err)
		}
		
		return nil
	}
	
	// Close 关闭去重器
	func (d *Deduplicator) Close() error {
		// 取消上下文，停止清理协程
		if d.cancel != nil {
			d.cancel()
		}
		
		// 停止定时器
		if d.cleanupTicker != nil {
			d.cleanupTicker.Stop()
		}
		
		// 保存到磁盘
		if d.enablePersistence {
			if err := d.saveToDisk(); err != nil {
				return fmt.Errorf("保存持久化数据失败: %w", err)
			}
		}
		
		// 清理缓存
		d.Clear()
		
		return nil
	}
	
	// HealthCheck 健康检查
	func (d *Deduplicator) HealthCheck() map[string]interface{} {
		stats := d.GetStats()
		cacheInfo := d.GetCacheInfo()
		
		health := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now(),
			"stats":     stats,
			"cache":     cacheInfo,
		}
		
		// 检查缓存使用率
		if usage, ok := cacheInfo["cache_usage_rate"].(float64); ok {
			if usage > 0.9 {
				health["status"] = "warning"
				health["message"] = "缓存使用率过高"
			}
		}
		
		// 检查错误率
		if stats.TotalChecks > 0 {
			errorRate := float64(stats.TotalChecks-stats.DuplicateFound-stats.UniquePages) / float64(stats.TotalChecks)
			if errorRate > 0.1 {
				health["status"] = "unhealthy"
				health["message"] = "错误率过高"
			}
		}
		
		return health
	}
	
	// DeduplicatorPool 去重器池
	type DeduplicatorPool struct {
		deduplicators []*Deduplicator
		current       int64
		mu            sync.RWMutex
	}
	
	// NewDeduplicatorPool 创建去重器池
	func NewDeduplicatorPool(size int, options ...DeduplicatorOption) (*DeduplicatorPool, error) {
		if size <= 0 {
			size = 1
		}
		
		pool := &DeduplicatorPool{
			deduplicators: make([]*Deduplicator, size),
		}
		
		for i := 0; i < size; i++ {
			dedup := NewDeduplicator(options...)
			pool.deduplicators[i] = dedup
		}
		
		return pool, nil
	}
	
	// GetDeduplicator 获取去重器实例（轮询）
	func (dp *DeduplicatorPool) GetDeduplicator() *Deduplicator {
		dp.mu.RLock()
		defer dp.mu.RUnlock()
		
		index := atomic.AddInt64(&dp.current, 1) % int64(len(dp.deduplicators))
		return dp.deduplicators[index]
	}
	
	// IsDuplicate 池级别的重复检查
	func (dp *DeduplicatorPool) IsDuplicate(url string, body io.Reader) (bool, string, float64, error) {
		dedup := dp.GetDeduplicator()
		return dedup.IsDuplicate(url, body)
	}
	
	// GetPoolStats 获取池统计信息
	func (dp *DeduplicatorPool) GetPoolStats() map[string]interface{} {
		dp.mu.RLock()
		defer dp.mu.RUnlock()
		
		poolStats := map[string]interface{}{
			"pool_size":      len(dp.deduplicators),
			"deduplicators":  make([]map[string]interface{}, len(dp.deduplicators)),
		}
		
		var totalChecks, totalDuplicates, totalUnique int64
		
		for i, dedup := range dp.deduplicators {
			stats := dedup.GetStats()
			cacheInfo := dedup.GetCacheInfo()
			
			dedupInfo := map[string]interface{}{
				"index": i,
				"stats": stats,
				"cache": cacheInfo,
			}
			
			poolStats["deduplicators"].([]map[string]interface{})[i] = dedupInfo
			
			totalChecks += stats.TotalChecks
			totalDuplicates += stats.DuplicateFound
			totalUnique += stats.UniquePages
		}
		
		poolStats["total_checks"] = totalChecks
		poolStats["total_duplicates"] = totalDuplicates
		poolStats["total_unique"] = totalUnique
		
		if totalChecks > 0 {
			poolStats["duplicate_rate"] = float64(totalDuplicates) / float64(totalChecks)
		}
		
		return poolStats
	}
	
	// Close 关闭池
	func (dp *DeduplicatorPool) Close() error {
		dp.mu.Lock()
		defer dp.mu.Unlock()
		
		var errors []error
		
		for i, dedup := range dp.deduplicators {
			if err := dedup.Close(); err != nil {
				errors = append(errors, fmt.Errorf("关闭去重器%d失败: %w", i, err))
			}
		}
		
		if len(errors) > 0 {
			return fmt.Errorf("关闭去重器池时发生错误: %v", errors)
		}
		
		return nil
	}
	
	// 工具函数
	
	// CompareSignatures 比较两个签名文件
	func CompareSignatures(file1, file2 string) (float64, error) {
		sig1, err := LoadSignatureFromFile(file1)
		if err != nil {
			return 0, fmt.Errorf("加载签名文件1失败: %w", err)
		}
		
		sig2, err := LoadSignatureFromFile(file2)
		if err != nil {
			return 0, fmt.Errorf("加载签名文件2失败: %w", err)
		}
		
		return sig1.Similarity(sig2), nil
	}
	
	// SaveSignatureToFile 保存签名到文件
	func SaveSignatureToFile(signature *PageSignature, filename string) error {
		file, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("创建文件失败: %w", err)
		}
		defer file.Close()
		
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		
		if err := encoder.Encode(signature); err != nil {
			return fmt.Errorf("编码签名失败: %w", err)
		}
		
		return nil
	}
	
	// LoadSignatureFromFile 从文件加载签名
	func LoadSignatureFromFile(filename string) (*PageSignature, error) {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("打开文件失败: %w", err)
		}
		defer file.Close()
		
		var signature PageSignature
		decoder := json.NewDecoder(file)
		
		if err := decoder.Decode(&signature); err != nil {
			return nil, fmt.Errorf("解码签名失败: %w", err)
		}
		
		return &signature, nil
	}
	
	// BatchGenerateSignatures 批量生成签名
	func BatchGenerateSignatures(urls []string, bodies []io.Reader, dimensions int) (map[string]*PageSignature, error) {
		if len(urls) != len(bodies) {
			return nil, fmt.Errorf("URLs和bodies数量不匹配")
		}
		
		results := make(map[string]*PageSignature)
		var mu sync.Mutex
		var wg sync.WaitGroup
		
		semaphore := make(chan struct{}, 10) // 限制并发数
		
		for i, url := range urls {
			wg.Add(1)
			go func(u string, body io.Reader) {
				defer wg.Done()
				
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				
				signature, err := GeneratePageSignature(body, dimensions)
				if err == nil {
					mu.Lock()
					results[u] = signature
					mu.Unlock()
				}
			}(url, bodies[i])
		}
		
		wg.Wait()
		return results, nil
	}
	