// Package dedup 提供了基于内容相似度的网页去重功能。
// 其核心思想类似于 Simhash 算法，用于快速判断两个文档的相似性。
package dedup

import (
	"bytes"
	"crypto/sha256" // 使用更现代的哈希算法
	"encoding/binary"
	"io"
	"math"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

const (
	// defaultVectorDimensions 决定了每个页面特征向量的大小。
	// 向量维度越高，对页面特征的描述越精细，但计算量和存储开销也越大。
	defaultVectorDimensions = 64
)

// PageSignature 代表一个已解析HTML页面的特征向量。
// 向量中的每个元素代表一个特征维度的权重。
type PageSignature []int

// GeneratePageSignature 从一个HTML文档创建一个特征向量（页面签名）。
//
// 算法步骤:
// 1. 解析HTML，遍历所有文本节点。
// 2. 对每个非空文本节点的内容计算哈希值。
// 3. 将哈希值映射到向量的一个维度上（通过取模运算）。
// 4. 增加该维度的权重。
// 最终得到的向量就代表了整个页面的文本内容分布特征。
func GeneratePageSignature(body io.Reader, dimensions int) (PageSignature, error) {
	if dimensions <= 0 {
		dimensions = defaultVectorDimensions
	}
	vector := make(PageSignature, dimensions)
	doc, err := html.Parse(body)
	if err != nil {
		return nil, err
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.TextNode && strings.TrimSpace(n.Data) != "" {
			h := sha256.New()
			h.Write([]byte(n.Data))
			hashBytes := h.Sum(nil)
			// 从哈希值中安全地取出一个uint64作为后续计算的基数。
			hashInt := binary.BigEndian.Uint64(hashBytes[:8])
			dimension := int(hashInt % uint64(dimensions))
			vector[dimension]++
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return vector, nil
}

// Similarity 计算两个页面签名之间的余弦相似度。
// 余弦相似度的值范围在-1到1之间，值越接近1，表示两个向量的方向越相似。
// 在这里，它被用来衡量两个页面内容的相似程度。
func (ps PageSignature) Similarity(other PageSignature) float64 {
	if len(ps) != len(other) || len(ps) == 0 {
		return 0.0
	}

	var dotProduct, mag1, mag2 float64
	for i := 0; i < len(ps); i++ {
		dotProduct += float64(ps[i] * other[i])
		mag1 += float64(ps[i] * ps[i])
		mag2 += float64(other[i] * other[i])
	}

	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(mag1) * math.Sqrt(mag2))
}

// Deduplicator 负责处理基于内容相似度的URL去重。
type Deduplicator struct {
	mu         sync.Mutex
	signatures map[string]PageSignature
	threshold  float64
}

// NewDeduplicator 创建一个新的去重器。
//
// 参数:
//
//	threshold (float64): 相似度阈值，介于0.0和1.0之间。
//	                     如果新页面与任何已有页面的相似度超过此阈值，则被视为重复。
//	                     如果提供的值小于等于0，将使用默认阈值0.95。
func NewDeduplicator(threshold float64) *Deduplicator {
	if threshold <= 0 {
		threshold = 0.95 // 设置默认阈值
	}
	return &Deduplicator{
		signatures: make(map[string]PageSignature),
		threshold:  threshold,
	}
}

// IsUnique 检查一个URL的内容是否是唯一的。
//
// 注意: 此方法当前的实现性能存在瓶颈。
// 每次检查都需要将新页面的签名与所有已存储的签名进行比较，时间复杂度为O(N)，
// 其中N是已存储签名的数量。对于大规模爬取，这可能会变得非常缓慢。
// 优化方向可以参考更完整的 Simhash 实现，例如使用汉明距离和索引表来快速查找相似项。
func (d *Deduplicator) IsUnique(url string, body io.Reader) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 读取body内容以备多次使用（一次用于生成签名，一次可能用于其他目的）。
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return false, err
	}

	currentSig, err := GeneratePageSignature(bytes.NewReader(bodyBytes), defaultVectorDimensions)
	if err != nil {
		return false, err
	}

	for _, sig := range d.signatures {
		if currentSig.Similarity(sig) > d.threshold {
			return false, nil // 发现相似页面，判定为重复。
		}
	}

	// 如果没有发现相似页面，则将当前签名存入map中，并判定为唯一。
	d.signatures[url] = currentSig
	return true, nil
}
