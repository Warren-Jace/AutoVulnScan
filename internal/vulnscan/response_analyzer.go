// Package vulnscan 提供了核心的漏洞扫描引擎和插件管理机制。
package vulnscan

import (
	"bytes"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"
)

// ResponseAnalysisType 响应分析类型
type ResponseAnalysisType string

const (
	// AnalysisContentLength 内容长度分析
	AnalysisContentLength ResponseAnalysisType = "content_length"
	// AnalysisStatusCode 状态码分析
	AnalysisStatusCode ResponseAnalysisType = "status_code"
	// AnalysisErrorPattern 错误模式分析
	AnalysisErrorPattern ResponseAnalysisType = "error_pattern"
	// AnalysisTimeBased 时间延迟分析
	AnalysisTimeBased ResponseAnalysisType = "time_based"
	// AnalysisBooleanBased 布尔逻辑分析
	AnalysisBooleanBased ResponseAnalysisType = "boolean_based"
	// AnalysisUnionBased 联合查询分析
	AnalysisUnionBased ResponseAnalysisType = "union_based"
	// AnalysisReflection 反射分析
	AnalysisReflection ResponseAnalysisType = "reflection"
	// AnalysisDOMAnalysis DOM分析
	AnalysisDOMAnalysis ResponseAnalysisType = "dom_analysis"
	// AnalysisWAFDetection WAF检测分析
	AnalysisWAFDetection ResponseAnalysisType = "waf_detection"
)

// AnalysisResult 分析结果
type AnalysisResult struct {
	Type         ResponseAnalysisType `json:"type"`
	IsVulnerable bool                `json:"is_vulnerable"`
	Confidence   float64             `json:"confidence"`
	Evidence     []Evidence          `json:"evidence"`
	Description  string              `json:"description"`
	Details      map[string]interface{} `json:"details"`
}

// ResponseAnalyzer 响应分析器接口
type ResponseAnalyzer interface {
	// AnalyzeResponse 分析响应
	AnalyzeResponse(baselineResp *HTTPResponse, testResp *HTTPResponse, payload string) ([]AnalysisResult, error)
	// AnalyzeResponses 分析多个响应
	AnalyzeResponses(baselineResp *HTTPResponse, testResps []*HTTPResponse, payloads []string) ([]AnalysisResult, error)
	// AnalyzeTimeBasedResponse 分析基于时间的响应
	AnalyzeTimeBasedResponse(testResp *HTTPResponse, expectedDelay time.Duration) (AnalysisResult, error)
	// AnalyzeBooleanBasedResponse 分析基于布尔的响应
	AnalyzeBooleanBasedResponse(trueResp *HTTPResponse, falseResp *HTTPResponse) (AnalysisResult, error)
	// AnalyzeErrorPatternResponse 分析错误模式响应
	AnalyzeErrorPatternResponse(testResp *HTTPResponse, errorPatterns []string) (AnalysisResult, error)
	// AnalyzeReflectionResponse 分析反射响应
	AnalyzeReflectionResponse(testResp *HTTPResponse, payload string) (AnalysisResult, error)
	// AnalyzeUnionBasedResponse 分析联合查询响应
	AnalyzeUnionBasedResponse(testResp *HTTPResponse, baselineResp *HTTPResponse) (AnalysisResult, error)
	// AnalyzeWAFResponse 分析WAF响应
	AnalyzeWAFResponse(testResp *HTTPResponse) (AnalysisResult, error)
	// CompareResponses 比较两个响应
	CompareResponses(resp1 *HTTPResponse, resp2 *HTTPResponse) (ResponseDifference, error)
	// CalculateConfidence 计算置信度
	CalculateConfidence(results []AnalysisResult) float64
	// AddErrorPattern 添加错误模式
	AddErrorPattern(pattern string, description string)
	// RemoveErrorPattern 移除错误模式
	RemoveErrorPattern(pattern string)
	// GetErrorPatterns 获取错误模式
	GetErrorPatterns() map[string]string
	// SetAnalysisConfig 设置分析配置
	SetAnalysisConfig(config AnalysisConfig)
	// GetAnalysisConfig 获取分析配置
	GetAnalysisConfig() AnalysisConfig
	// GetStats 获取分析器统计信息
	GetStats() AnalyzerStats
}

// ResponseDifference 响应差异
type ResponseDifference struct {
	StatusCodeChanged bool    `json:"status_code_changed"`
	ContentLengthDiff int     `json:"content_length_diff"`
	ContentLengthRatio float64 `json:"content_length_ratio"`
	Similarity        float64 `json:"similarity"`
	Differences       []string `json:"differences"`
	Similarities      []string `json:"similarities"`
	WordsAdded        []string `json:"words_added"`
	WordsRemoved      []string `json:"words_removed"`
	LinesAdded        int      `json:"lines_added"`
	LinesRemoved      int      `json:"lines_removed"`
	ErrorPatterns     []string `json:"error_patterns"`
	CustomPatterns    []string `json:"custom_patterns"`
}

// AnalysisConfig 分析配置
type AnalysisConfig struct {
	ContentLengthThreshold    int         `json:"content_length_threshold"`
	ContentLengthRatioThreshold float64   `json:"content_length_ratio_threshold"`
	SimilarityThreshold       float64     `json:"similarity_threshold"`
	TimeDelayThreshold        time.Duration `json:"time_delay_threshold"`
	BooleanSimilarityThreshold float64   `json:"boolean_similarity_threshold"`
	ErrorPatternThreshold     int         `json:"error_pattern_threshold"`
	ReflectionThreshold       int         `json:"reflection_threshold"`
	WAFThreshold              int         `json:"waf_threshold"`
	ConfidenceThreshold       float64     `json:"confidence_threshold"`
	EnableAdvancedAnalysis    bool        `json:"enable_advanced_analysis"`
	EnableWordDiffAnalysis     bool        `json:"enable_word_diff_analysis"`
	EnableLineDiffAnalysis     bool        `json:"enable_line_diff_analysis"`
	EnablePatternAnalysis      bool        `json:"enable_pattern_analysis"`
	EnableStatisticalAnalysis  bool        `json:"enable_statistical_analysis"`
	CustomPatterns            []string    `json:"custom_patterns"`
	IgnorePatterns            []string    `json:"ignore_patterns"`
}

// AnalyzerStats 分析器统计信息
type AnalyzerStats struct {
	TotalAnalyses      int64                    `json:"total_analyses"`
	VulnerabilitiesFound int64                  `json:"vulnerabilities_found"`
	AnalysesByType     map[ResponseAnalysisType]int64 `json:"analyses_by_type"`
	AverageConfidence  float64                  `json:"average_confidence"`
	AverageResponseTime time.Duration           `json:"average_response_time"`
	ErrorPatternHits   int64                    `json:"error_pattern_hits"`
	ReflectionHits     int64                    `json:"reflection_hits"`
	TimeBasedHits      int64                    `json:"time_based_hits"`
	BooleanBasedHits   int64                    `json:"boolean_based_hits"`
	WAFHits            int64                    `json:"waf_hits"`
}

// DefaultResponseAnalyzer 默认响应分析器
type DefaultResponseAnalyzer struct {
	errorPatterns map[string]string
	config        AnalysisConfig
	stats         AnalyzerStats
}

// NewDefaultResponseAnalyzer 创建默认响应分析器
func NewDefaultResponseAnalyzer() *DefaultResponseAnalyzer {
	analyzer := &DefaultResponseAnalyzer{
		errorPatterns: make(map[string]string),
		config: AnalysisConfig{
			ContentLengthThreshold:      100,
			ContentLengthRatioThreshold: 0.1,
			SimilarityThreshold:         0.8,
			TimeDelayThreshold:          5 * time.Second,
			BooleanSimilarityThreshold: 0.2,
			ErrorPatternThreshold:      1,
			ReflectionThreshold:         1,
			WAFThreshold:               3,
			ConfidenceThreshold:        0.7,
			EnableAdvancedAnalysis:     true,
			EnableWordDiffAnalysis:      true,
			EnableLineDiffAnalysis:      true,
			EnablePatternAnalysis:       true,
			EnableStatisticalAnalysis:   true,
			CustomPatterns:             []string{},
			IgnorePatterns:             []string{},
		},
		stats: AnalyzerStats{
			AnalysesByType: make(map[ResponseAnalysisType]int64),
		},
	}

	// 初始化错误模式
	analyzer.initializeErrorPatterns()

	return analyzer
}

// initializeErrorPatterns 初始化错误模式
func (ra *DefaultResponseAnalyzer) initializeErrorPatterns() {
	// SQL错误模式
	ra.errorPatterns["SQL syntax"] = "SQL语法错误"
	ra.errorPatterns["MySQL server"] = "MySQL服务器错误"
	ra.errorPatterns["ORA-[0-9]+:"] = "Oracle数据库错误"
	ra.errorPatterns["Microsoft OLE DB Provider"] = "Microsoft OLE DB错误"
	ra.errorPatterns["PostgreSQL query failed"] = "PostgreSQL查询失败"
	ra.errorPatterns["SQLite error"] = "SQLite错误"
	ra.errorPatterns["Warning: mysql_"] = "MySQL警告"
	ra.errorPatterns["Fatal error"] = "致命错误"
	ra.errorPatterns["Unclosed quotation mark"] = "未闭合的引号"
	ra.errorPatterns["Syntax error"] = "语法错误"

	// XSS错误模式
	ra.errorPatterns["Cross-site scripting"] = "跨站脚本错误"
	ra.errorPatterns["XSS detected"] = "检测到XSS"
	ra.errorPatterns["Potential XSS attack"] = "潜在的XSS攻击"
	ra.errorPatterns["HTML injection"] = "HTML注入"
	ra.errorPatterns["Script tag detected"] = "检测到脚本标签"
	ra.errorPatterns["JavaScript error"] = "JavaScript错误"
	ra.errorPatterns["Invalid character"] = "无效字符"
	ra.errorPatterns["Malformed input"] = "格式错误的输入"

	// WAF检测模式
	ra.errorPatterns["Web Application Firewall"] = "Web应用防火墙"
	ra.errorPatterns["ModSecurity"] = "ModSecurity防火墙"
	ra.errorPatterns["AWS WAF"] = "AWS Web应用防火墙"
	ra.errorPatterns["Cloudflare"] = "Cloudflare防火墙"
	ra.errorPatterns["Forbidden"] = "禁止访问"
	ra.errorPatterns["Access denied"] = "访问被拒绝"
	ra.errorPatterns["Request blocked"] = "请求被阻止"
	ra.errorPatterns["Suspicious activity"] = "可疑活动"
	ra.errorPatterns["Security violation"] = "安全违规"
	ra.errorPatterns["Attack detected"] = "检测到攻击"
}

// AnalyzeResponse 分析响应
func (ra *DefaultResponseAnalyzer) AnalyzeResponse(baselineResp *HTTPResponse, testResp *HTTPResponse, payload string) ([]AnalysisResult, error) {
	var results []AnalysisResult

	// 1. 内容长度分析
	lengthResult := ra.analyzeContentLength(baselineResp, testResp)
	results = append(results, lengthResult)

	// 2. 状态码分析
	statusResult := ra.analyzeStatusCode(baselineResp, testResp)
	results = append(results, statusResult)

	// 3. 错误模式分析
	errorResult, err := ra.analyzeErrorPattern(testResp)
	if err != nil {
		return nil, err
	}
	results = append(results, errorResult)

	// 4. 反射分析
	reflectionResult := ra.analyzeReflection(testResp, payload)
	results = append(results, reflectionResult)

	// 5. WAF检测分析
	wafResult := ra.analyzeWAF(testResp)
	results = append(results, wafResult)

	// 更新统计信息
	ra.updateStats(results)

	return results, nil
}

// AnalyzeResponses 分析多个响应
func (ra *DefaultResponseAnalyzer) AnalyzeResponses(baselineResp *HTTPResponse, testResps []*HTTPResponse, payloads []string) ([]AnalysisResult, error) {
	var results []AnalysisResult

	// 分析每个测试响应
	for i, testResp := range testResps {
		payload := ""
		if i < len(payloads) {
			payload = payloads[i]
		}

		respResults, err := ra.AnalyzeResponse(baselineResp, testResp, payload)
		if err != nil {
			return nil, err
		}

		results = append(results, respResults...)
	}

	return results, nil
}

// AnalyzeTimeBasedResponse 分析基于时间的响应
func (ra *DefaultResponseAnalyzer) AnalyzeTimeBasedResponse(testResp *HTTPResponse, expectedDelay time.Duration) (AnalysisResult, error) {
	result := AnalysisResult{
		Type:        AnalysisTimeBased,
		Description: "基于时间的响应分析",
		Details:     make(map[string]interface{}),
	}

	// 检查响应时间是否超过预期延迟
	actualDelay := testResp.ResponseTime
	result.Details["expected_delay"] = expectedDelay.String()
	result.Details["actual_delay"] = actualDelay.String()

	// 计算置信度
	if actualDelay >= expectedDelay {
		// 计算延迟比例
		delayRatio := float64(actualDelay) / float64(expectedDelay)
		result.Details["delay_ratio"] = delayRatio

		// 基于延迟比例计算置信度
		if delayRatio >= 2.0 {
			result.Confidence = 0.9
		} else if delayRatio >= 1.5 {
			result.Confidence = 0.8
		} else {
			result.Confidence = 0.7
		}

		result.IsVulnerable = true
		result.Evidence = append(result.Evidence, Evidence{
			Type:        "time_delay",
			Description: "响应时间显著延长",
			Value:       actualDelay.String(),
			Confidence:  result.Confidence,
		})
	} else {
		result.Confidence = 0.0
		result.IsVulnerable = false
	}

	// 更新统计信息
	ra.stats.AnalysesByType[AnalysisTimeBased]++
	if result.IsVulnerable {
		ra.stats.TimeBasedHits++
		ra.stats.VulnerabilitiesFound++
	}
	ra.stats.TotalAnalyses++

	return result, nil
}

// AnalyzeBooleanBasedResponse 分析基于布尔的响应
func (ra *DefaultResponseAnalyzer) AnalyzeBooleanBasedResponse(trueResp *HTTPResponse, falseResp *HTTPResponse) (AnalysisResult, error) {
	result := AnalysisResult{
		Type:        AnalysisBooleanBased,
		Description: "基于布尔的响应分析",
		Details:     make(map[string]interface{}),
	}

	// 比较两个响应的差异
	diff, err := ra.CompareResponses(trueResp, falseResp)
	if err != nil {
		return AnalysisResult{}, err
	}

	result.Details["similarity"] = diff.Similarity
	result.Details["content_length_diff"] = diff.ContentLengthDiff
	result.Details["content_length_ratio"] = diff.ContentLengthRatio

	// 如果相似度低于阈值，则可能存在漏洞
	if diff.Similarity < ra.config.BooleanSimilarityThreshold {
		result.IsVulnerable = true

		// 基于相似度计算置信度
		confidence := 1.0 - diff.Similarity
		if confidence > 1.0 {
			confidence = 1.0
		}
		result.Confidence = confidence

		result.Evidence = append(result.Evidence, Evidence{
			Type:        "boolean_difference",
			Description: "布尔条件导致响应显著差异",
			Value:       fmt.Sprintf("相似度: %.2f", diff.Similarity),
			Confidence:  result.Confidence,
		})
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	// 更新统计信息
	ra.stats.AnalysesByType[AnalysisBooleanBased]++
	if result.IsVulnerable {
		ra.stats.BooleanBasedHits++
		ra.stats.VulnerabilitiesFound++
	}
	ra.stats.TotalAnalyses++

	return result, nil
}

// AnalyzeErrorPatternResponse 分析错误模式响应
func (ra *DefaultResponseAnalyzer) AnalyzeErrorPatternResponse(testResp *HTTPResponse, errorPatterns []string) (AnalysisResult, error) {
	result := AnalysisResult{
		Type:        AnalysisErrorPattern,
		Description: "错误模式响应分析",
		Details:     make(map[string]interface{}),
	}

	// 如果没有提供错误模式，使用默认的错误模式
	if len(errorPatterns) == 0 {
		errorPatterns = ra.getDefaultErrorPatterns()
	}

	// 检查响应中是否包含错误模式
	matchedPatterns := ra.findErrorPatterns(testResp.Body, errorPatterns)
	result.Details["matched_patterns"] = matchedPatterns

	// 如果匹配到错误模式，则可能存在漏洞
	if len(matchedPatterns) >= ra.config.ErrorPatternThreshold {
		result.IsVulnerable = true

		// 基于匹配的模式数量计算置信度
		confidence := float64(len(matchedPatterns)) / float64(len(errorPatterns))
		if confidence > 1.0 {
			confidence = 1.0
		}
		result.Confidence = confidence

		// 添加证据
		for _, pattern := range matchedPatterns {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "error_pattern",
				Description: "检测到错误模式",
				Value:       pattern,
				Confidence:  result.Confidence,
			})
		}
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	// 更新统计信息
	ra.stats.AnalysesByType[AnalysisErrorPattern]++
	if result.IsVulnerable {
		ra.stats.ErrorPatternHits++
		ra.stats.VulnerabilitiesFound++
	}
	ra.stats.TotalAnalyses++

	return result, nil
}

// AnalyzeReflectionResponse 分析反射响应
func (ra *DefaultResponseAnalyzer) AnalyzeReflectionResponse(testResp *HTTPResponse, payload string) (AnalysisResult, error) {
	result := AnalysisResult{
		Type:        AnalysisReflection,
		Description: "反射响应分析",
		Details:     make(map[string]interface{}),
	}

	// 检查payload是否在响应中反射
	reflectionCount := ra.countReflections(testResp.Body, payload)
	result.Details["reflection_count"] = reflectionCount

	// 如果反射次数超过阈值，则可能存在漏洞
	if reflectionCount >= ra.config.ReflectionThreshold {
		result.IsVulnerable = true

		// 基于反射次数计算置信度
		confidence := 0.7 + (float64(reflectionCount-1) * 0.1)
		if confidence > 1.0 {
			confidence = 1.0
		}
		result.Confidence = confidence

		result.Evidence = append(result.Evidence, Evidence{
			Type:        "reflection",
			Description: "检测到输入反射",
			Value:       fmt.Sprintf("反射次数: %d", reflectionCount),
			Confidence:  result.Confidence,
		})
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	// 更新统计信息
	ra.stats.AnalysesByType[AnalysisReflection]++
	if result.IsVulnerable {
		ra.stats.ReflectionHits++
		ra.stats.VulnerabilitiesFound++
	}
	ra.stats.TotalAnalyses++

	return result, nil
}

// AnalyzeUnionBasedResponse 分析联合查询响应
func (ra *DefaultResponseAnalyzer) AnalyzeUnionBasedResponse(testResp *HTTPResponse, baselineResp *HTTPResponse) (AnalysisResult, error) {
	result := AnalysisResult{
		Type:        AnalysisUnionBased,
		Description: "联合查询响应分析",
		Details:     make(map[string]interface{}),
	}

	// 比较两个响应的差异
	diff, err := ra.CompareResponses(baselineResp, testResp)
	if err != nil {
		return AnalysisResult{}, err
	}

	result.Details["similarity"] = diff.Similarity
	result.Details["content_length_diff"] = diff.ContentLengthDiff
	result.Details["content_length_ratio"] = diff.ContentLengthRatio

	// 检查响应中是否包含数据库查询结果的特征
	// 这里可以添加更复杂的逻辑来检测联合查询的结果
	unionFeatures := ra.detectUnionFeatures(testResp.Body)
	result.Details["union_features"] = unionFeatures

	// 如果检测到联合查询特征，则可能存在漏洞
	if len(unionFeatures) > 0 && diff.ContentLengthDiff > ra.config.ContentLengthThreshold {
		result.IsVulnerable = true

		// 基于特征数量和内容长度差异计算置信度
		confidence := 0.6 + (float64(len(unionFeatures)) * 0.1)
		if confidence > 1.0 {
			confidence = 1.0
		}
		result.Confidence = confidence

		// 添加证据
		for _, feature := range unionFeatures {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "union_feature",
				Description: "检测到联合查询特征",
				Value:       feature,
				Confidence:  result.Confidence,
			})
		}
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	// 更新统计信息
	ra.stats.AnalysesByType[AnalysisUnionBased]++
	if result.IsVulnerable {
		ra.stats.VulnerabilitiesFound++
	}
	ra.stats.TotalAnalyses++

	return result, nil
}

// AnalyzeWAFResponse 分析WAF响应
func (ra *DefaultResponseAnalyzer) AnalyzeWAFResponse(testResp *HTTPResponse) (AnalysisResult, error) {
	result := AnalysisResult{
		Type:        AnalysisWAFDetection,
		Description: "WAF响应分析",
		Details:     make(map[string]interface{}),
	}

	// 检查响应中是否包含WAF特征
	wafFeatures := ra.detectWAFFeatures(testResp)
	result.Details["waf_features"] = wafFeatures

	// 如果检测到WAF特征，则可能存在WAF
	if len(wafFeatures) >= ra.config.WAFThreshold {
		result.IsVulnerable = true // 这里IsVulnerable表示检测到WAF

		// 基于特征数量计算置信度
		confidence := 0.7 + (float64(len(wafFeatures)-1) * 0.1)
		if confidence > 1.0 {
			confidence = 1.0
		}
		result.Confidence = confidence

		// 添加证据
		for _, feature := range wafFeatures {
			result.Evidence = append(result.Evidence, Evidence{
				Type:        "waf_feature",
				Description: "检测到WAF特征",
				Value:       feature,
				Confidence:  result.Confidence,
			})
		}
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	// 更新统计信息
	ra.stats.AnalysesByType[AnalysisWAFDetection]++
	if result.IsVulnerable {
		ra.stats.WAFHits++
	}
	ra.stats.TotalAnalyses++

	return result, nil
}

// CompareResponses 比较两个响应
func (ra *DefaultResponseAnalyzer) CompareResponses(resp1 *HTTPResponse, resp2 *HTTPResponse) (ResponseDifference, error) {
	diff := ResponseDifference{
		Differences:  make([]string, 0),
		Similarities: make([]string, 0),
		WordsAdded:    make([]string, 0),
		WordsRemoved:  make([]string, 0),
		ErrorPatterns: make([]string, 0),
		CustomPatterns: make([]string, 0),
	}

	// 比较状态码
	diff.StatusCodeChanged = resp1.StatusCode != resp2.StatusCode

	// 比较内容长度
	len1 := len(resp1.Body)
	len2 := len(resp2.Body)
	diff.ContentLengthDiff = len2 - len1
	if len1 > 0 {
		diff.ContentLengthRatio = math.Abs(float64(diff.ContentLengthDiff) / float64(len1))
	} else if len2 > 0 {
		diff.ContentLengthRatio = 1.0
	} else {
		diff.ContentLengthRatio = 0.0
	}

	// 计算相似度
	diff.Similarity = ra.calculateSimilarity(resp1.Body, resp2.Body)

	// 如果启用了高级分析
	if ra.config.EnableAdvancedAnalysis {
		// 词差异分析
		if ra.config.EnableWordDiffAnalysis {
			wordsAdded, wordsRemoved := ra.analyzeWordDiff(resp1.Body, resp2.Body)
			diff.WordsAdded = wordsAdded
			diff.WordsRemoved = wordsRemoved
		}

		// 行差异分析
		if ra.config.EnableLineDiffAnalysis {
			linesAdded, linesRemoved := ra.analyzeLineDiff(resp1.Body, resp2.Body)
			diff.LinesAdded = linesAdded
			diff.LinesRemoved = linesRemoved
		}

		// 模式分析
		if ra.config.EnablePatternAnalysis {
			errorPatterns := ra.findErrorPatterns(resp2.Body, ra.getDefaultErrorPatterns())
			diff.ErrorPatterns = errorPatterns

			customPatterns := ra.findCustomPatterns(resp2.Body)
			diff.CustomPatterns = customPatterns
		}
	}

	return diff, nil
}

// CalculateConfidence 计算置信度
func (ra *DefaultResponseAnalyzer) CalculateConfidence(results []AnalysisResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	// 计算平均置信度
	totalConfidence := 0.0
	vulnerableCount := 0

	for _, result := range results {
		if result.IsVulnerable {
			totalConfidence += result.Confidence
			vulnerableCount++
		}
	}

	if vulnerableCount == 0 {
		return 0.0
	}

	avgConfidence := totalConfidence / float64(vulnerableCount)

	// 如果平均置信度超过阈值，则返回平均置信度
	if avgConfidence >= ra.config.ConfidenceThreshold {
		return avgConfidence
	}

	// 否则返回0
	return 0.0
}

// AddErrorPattern 添加错误模式
func (ra *DefaultResponseAnalyzer) AddErrorPattern(pattern string, description string) {
	ra.errorPatterns[pattern] = description
}

// RemoveErrorPattern 移除错误模式
func (ra *DefaultResponseAnalyzer) RemoveErrorPattern(pattern string) {
	delete(ra.errorPatterns, pattern)
}

// GetErrorPatterns 获取错误模式
func (ra *DefaultResponseAnalyzer) GetErrorPatterns() map[string]string {
	// 返回错误模式的副本
	patterns := make(map[string]string)
	for k, v := range ra.errorPatterns {
		patterns[k] = v
	}
	return patterns
}

// SetAnalysisConfig 设置分析配置
func (ra *DefaultResponseAnalyzer) SetAnalysisConfig(config AnalysisConfig) {
	ra.config = config
}

// GetAnalysisConfig 获取分析配置
func (ra *DefaultResponseAnalyzer) GetAnalysisConfig() AnalysisConfig {
	return ra.config
}

// GetStats 获取分析器统计信息
func (ra *DefaultResponseAnalyzer) GetStats() AnalyzerStats {
	return ra.stats
}

// analyzeContentLength 分析内容长度
func (ra *DefaultResponseAnalyzer) analyzeContentLength(baselineResp *HTTPResponse, testResp *HTTPResponse) AnalysisResult {
	result := AnalysisResult{
		Type:        AnalysisContentLength,
		Description: "内容长度分析",
		Details:     make(map[string]interface{}),
	}

	// 计算内容长度差异
	baselineLength := len(baselineResp.Body)
	testLength := len(testResp.Body)
	diff := testLength - baselineLength

	result.Details["baseline_length"] = baselineLength
	result.Details["test_length"] = testLength
	result.Details["length_diff"] = diff

	// 计算长度比例
	ratio := 0.0
	if baselineLength > 0 {
		ratio = math.Abs(float64(diff) / float64(baselineLength))
	} else if testLength > 0 {
		ratio = 1.0
	}
	result.Details["length_ratio"] = ratio

	// 如果长度差异超过阈值，则可能存在漏洞
	if math.Abs(float64(diff)) > float64(ra.config.ContentLengthThreshold) || ratio > ra.config.ContentLengthRatioThreshold {
		result.IsVulnerable = true

		// 基于长度差异计算置信度
		confidence := 0.5 + (ratio * 0.5)
		if confidence > 1.0 {
			confidence = 1.0
		}
		result.Confidence = confidence

		result.Evidence = append(result.Evidence, Evidence{
			Type:        "content_length",
			Description: "内容长度显著变化",
			Value:       fmt.Sprintf("差异: %d, 比例: %.2f", diff, ratio),
			Confidence:  result.Confidence,
		})
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	return result
}

// analyzeStatusCode 分析状态码
func (ra *DefaultResponseAnalyzer) analyzeStatusCode(baselineResp *HTTPResponse, testResp *HTTPResponse) AnalysisResult {
	result := AnalysisResult{
		Type:        AnalysisStatusCode,
		Description: "状态码分析",
		Details:     make(map[string]interface{}),
	}

	// 比较状态码
	baselineStatus := baselineResp.StatusCode
	testStatus := testResp.StatusCode
	statusChanged := baselineStatus != testStatus

	result.Details["baseline_status"] = baselineStatus
	result.Details["test_status"] = testStatus
	result.Details["status_changed"] = statusChanged

	// 如果状态码发生变化，则可能存在漏洞
	if statusChanged {
		result.IsVulnerable = true

		// 基于状态码变化计算置信度
		confidence := 0.7
		if IsServerErrorStatus(testStatus) {
			confidence = 0.9
		} else if IsClientErrorStatus(testStatus) {
			confidence = 0.8
		}
		result.Confidence = confidence

		result.Evidence = append(result.Evidence, Evidence{
			Type:        "status_code",
			Description: "状态码发生变化",
			Value:       fmt.Sprintf("%d -> %d", baselineStatus, testStatus),
			Confidence:  result.Confidence,
		})
	} else {
		result.IsVulnerable = false
		result.Confidence = 0.0
	}

	return result
}

// analyzeErrorPattern 分析错误模式
func (ra *DefaultResponseAnalyzer) analyzeErrorPattern(testResp *HTTPResponse) (AnalysisResult, error) {
	return ra.AnalyzeErrorPatternResponse(testResp, ra.getDefaultErrorPatterns())
}

// analyzeReflection 分析反射
func (ra *DefaultResponseAnalyzer) analyzeReflection(testResp *HTTPResponse, payload string) AnalysisResult {
	return ra.AnalyzeReflectionResponse(testResp, payload)
}

// analyzeWAF 分析WAF
func (ra *DefaultResponseAnalyzer) analyzeWAF(testResp *HTTPResponse) AnalysisResult {
	result, err := ra.AnalyzeWAFResponse(testResp)
	if err != nil {
		log.Error().Err(err).Msg("分析WAF响应失败")
		return AnalysisResult{
			Type:        AnalysisWAFDetection,
			IsVulnerable: false,
			Confidence:   0.0,
			Description:  "WAF响应分析失败",
			Details:      map[string]interface{}{"error": err.Error()},
		}
	}
	return result
}

// getDefaultErrorPatterns 获取默认错误模式
func (ra *DefaultResponseAnalyzer) getDefaultErrorPatterns() []string {
	patterns := make([]string, 0, len(ra.errorPatterns))
	for pattern := range ra.errorPatterns {
		patterns = append(patterns, pattern)
	}
	return patterns
}

// findErrorPatterns 查找错误模式
func (ra *DefaultResponseAnalyzer) findErrorPatterns(text string, patterns []string) []string {
	var matchedPatterns []string

	for _, pattern := range patterns {
		matched, err := regexp.MatchString(pattern, text)
		if err != nil {
			log.Error().Err(err).Str("pattern", pattern).Msg("编译正则表达式失败")
			continue
		}

		if matched {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	return matchedPatterns
}

// findCustomPatterns 查找自定义模式
func (ra *DefaultResponseAnalyzer) findCustomPatterns(text string) []string {
	if len(ra.config.CustomPatterns) == 0 {
		return []string{}
	}

	var matchedPatterns []string

	for _, pattern := range ra.config.CustomPatterns {
		matched, err := regexp.MatchString(pattern, text)
		if err != nil {
			log.Error().Err(err).Str("pattern", pattern).Msg("编译自定义正则表达式失败")
			continue
		}

		if matched {
			matchedPatterns = append(matchedPatterns, pattern)
		}
	}

	return matchedPatterns
}

// countReflections 计算反射次数
func (ra *DefaultResponseAnalyzer) countReflections(text, payload string) int {
	if payload == "" {
		return 0
	}

	count := strings.Count(text, payload)
	return count
}

// detectUnionFeatures 检测联合查询特征
func (ra *DefaultResponseAnalyzer) detectUnionFeatures(text string) []string {
	var features []string

	// 检查常见的联合查询结果特征
	unionPatterns := []string{
		`[0-9]+, [0-9]+, [0-9]+`,  // 数字序列
		`[a-zA-Z0-9_]+@[a-zA-Z0-9_]+\.[a-zA-Z]{2,}`,  // 电子邮件格式
		`[0-9]{4}-[0-9]{2}-[0-9]{2}`,  // 日期格式
		`[A-Z][a-z]+ [A-Z][a-z]+`,  // 全名格式
		`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`,  // IP地址格式
	}

	for _, pattern := range unionPatterns {
		matched, err := regexp.MatchString(pattern, text)
		if err != nil {
			log.Error().Err(err).Str("pattern", pattern).Msg("编译联合查询正则表达式失败")
			continue
		}

		if matched {
			features = append(features, pattern)
		}
	}

	return features
}

// detectWAFFeatures 检测WAF特征
func (ra *DefaultResponseAnalyzer) detectWAFFeatures(resp *HTTPResponse) []string {
	var features []string

	// 检查响应头中的WAF特征
	wafHeaders := map[string]string{
		"server":           "ModSecurity|Cloudflare|AWS WAF",
		"x-powered-by":     "ModSecurity",
		"x-waf-status":     "blocked|denied",
		"x-sucuri-cache":   "miss|hit",
		"x-sucuri-id":      "[0-9]+",
	}

	for header, patterns := range wafHeaders {
		if value, exists := resp.Headers[header]; exists {
			matchedPatterns := ra.findErrorPatterns(value, strings.Split(patterns, "|"))
			for _, pattern := range matchedPatterns {
				features = append(features, fmt.Sprintf("header:%s:%s", header, pattern))
			}
		}
	}

	// 检查响应体中的WAF特征
	wafPatterns := []string{
		"Web Application Firewall",
		"ModSecurity",
		"AWS WAF",
		"Cloudflare",
		"Forbidden",
		"Access denied",
		"Request blocked",
		"Suspicious activity",
		"Security violation",
		"Attack detected",
		"incident ID",
		"reference ID",
	}

	matchedPatterns := ra.findErrorPatterns(resp.Body, wafPatterns)
	for _, pattern := range matchedPatterns {
		features = append(features, fmt.Sprintf("body:%s", pattern))
	}

	// 检查状态码
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		features = append(features, fmt.Sprintf("status:%d", resp.StatusCode))
	}

	return features
}

// calculateSimilarity 计算相似度
func (ra *DefaultResponseAnalyzer) calculateSimilarity(text1, text2 string) float64 {
	if text1 == "" && text2 == "" {
		return 1.0
	}

	if text1 == "" || text2 == "" {
		return 0.0
	}

	// 使用简单的编辑距离算法计算相似度
	distance := ra.calculateEditDistance(text1, text2)
	maxLen := max(len(text1), len(text2))
	similarity := 1.0 - (float64(distance) / float64(maxLen))

	return similarity
}

// calculateEditDistance 计算编辑距离
func (ra *DefaultResponseAnalyzer) calculateEditDistance(text1, text2 string) int {
	r1 := []rune(text1)
	r2 := []rune(text2)

	m := len(r1)
	n := len(r2)

	// 创建距离矩阵
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	// 初始化矩阵
	for i := 0; i <= m; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = j
	}

	// 填充矩阵
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if r1[i-1] == r2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = min(min(dp[i-1][j], dp[i][j-1]), dp[i-1][j-1]) + 1
			}
		}
	}

	return dp[m][n]
}

// analyzeWordDiff 分析词差异
func (ra *DefaultResponseAnalyzer) analyzeWordDiff(text1, text2 string) ([]string, []string) {
	words1 := ra.splitIntoWords(text1)
	words2 := ra.splitIntoWords(text2)

	// 创建单词频率映射
	freq1 := make(map[string]int)
	freq2 := make(map[string]int)

	for _, word := range words1 {
		freq1[word]++
	}

	for _, word := range words2 {
		freq2[word]++
	}

	// 找出添加和删除的单词
	var wordsAdded, wordsRemoved []string

	// 找出添加的单词
	for word, count2 := range freq2 {
		count1, exists := freq1[word]
		if !exists {
			wordsAdded = append(wordsAdded, word)
		} else if count2 > count1 {
			for i := 0; i < count2-count1; i++ {
				wordsAdded = append(wordsAdded, word)
			}
		}
	}

	// 找出删除的单词
	for word, count1 := range freq1 {
		count2, exists := freq2[word]
		if !exists {
			wordsRemoved = append(wordsRemoved, word)
		} else if count1 > count2 {
			for i := 0; i < count1-count2; i++ {
				wordsRemoved = append(wordsRemoved, word)
			}
		}
	}

	return wordsAdded, wordsRemoved
}

// analyzeLineDiff 分析行差异
func (ra *DefaultResponseAnalyzer) analyzeLineDiff(text1, text2 string) (int, int) {
	lines1 := strings.Split(text1, "\n")
	lines2 := strings.Split(text2, "\n")

	// 创建行频率映射
	freq1 := make(map[string]int)
	freq2 := make(map[string]int)

	for _, line := range lines1 {
		freq1[line]++
	}

	for _, line := range lines2 {
		freq2[line]++
	}

	// 计算添加和删除的行数
	linesAdded := 0
	linesRemoved := 0

	// 计算添加的行数
	for line, count2 := range freq2 {
		count1, exists := freq1[line]
		if !exists {
			linesAdded += count2
		} else if count2 > count1 {
			linesAdded += count2 - count1
		}
	}

	// 计算删除的行数
	for line, count1 := range freq1 {
		count2, exists := freq2[line]
		if !exists {
			linesRemoved += count1
		} else if count1 > count2 {
			linesRemoved += count1 - count2
		}
	}

	return linesAdded, linesRemoved
}

// splitIntoWords 将文本分割为单词
func (ra *DefaultResponseAnalyzer) splitIntoWords(text string) []string {
	var words []string
	var currentWord strings.Builder

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			currentWord.WriteRune(r)
		} else {
			if currentWord.Len() > 0 {
				words = append(words, currentWord.String())
				currentWord.Reset()
			}
		}
	}

	// 添加最后一个单词
	if currentWord.Len() > 0 {
		words = append(words, currentWord.String())
	}

	return words
}

// updateStats 更新统计信息
func (ra *DefaultResponseAnalyzer) updateStats(results []AnalysisResult) {
	ra.stats.TotalAnalyses++

	// 更新按类型统计
	for _, result := range results {
		ra.stats.AnalysesByType[result.Type]++
		if result.IsVulnerable {
			ra.stats.VulnerabilitiesFound++
		}
	}

	// 更新平均置信度
	totalConfidence := 0.0
	vulnerableCount := 0

	for _, result := range results {
		if result.IsVulnerable {
			totalConfidence += result.Confidence
			vulnerableCount++
		}
	}

	if vulnerableCount > 0 {
		totalAnalyses := float64(ra.stats.TotalAnalyses)
		currentAvg := ra.stats.AverageConfidence
		newAvg := (currentAvg*(totalAnalyses-1) + totalConfidence/float64(vulnerableCount)) / totalAnalyses
		ra.stats.AverageConfidence = newAvg
	}
}

// 辅助函数

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func fmt.Sprintf(format string, a ...interface{}) string {
	return "" // 实际实现中应该使用标准库的fmt.Sprintf
}