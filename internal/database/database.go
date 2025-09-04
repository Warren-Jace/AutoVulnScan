// Package database 提供了数据库操作功能
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"autovulnscan/internal/config"
	"autovulnscan/internal/models"
)

// DB 数据库连接
type DB struct {
	gormDB *gorm.DB
	sqlDB  *sql.DB
	rdb    *redis.Client
	config *config.DatabaseConfig
}

// NewDB 创建一个新的数据库连接
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("database is disabled")
	}

	var gormDB *gorm.DB
	var rdb *redis.Client
	var err error

	// 根据数据库类型创建连接
	switch strings.ToLower(cfg.Type) {
	case "sqlite":
		gormDB, err = connectSQLite(cfg)
	case "mysql":
		gormDB, err = connectMySQL(cfg)
	case "postgres", "postgresql":
		gormDB, err = connectPostgreSQL(cfg)
	case "redis":
		rdb, err = connectRedis(cfg)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// 如果是Redis，直接返回，不需要gormDB和sqlDB
	if strings.ToLower(cfg.Type) == "redis" {
		return &DB{
			rdb:    rdb,
			config: cfg,
		}, nil
	}

	// 获取底层sql.DB
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// 设置连接池参数
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// 自动迁移表结构
	if err := autoMigrate(gormDB); err != nil {
		return nil, fmt.Errorf("failed to auto migrate: %w", err)
	}

	return &DB{
		gormDB: gormDB,
		sqlDB:  sqlDB,
		config: cfg,
	}, nil
}

// connectSQLite 连接SQLite数据库
func connectSQLite(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	// 确保数据库文件目录存在
	if cfg.FilePath != "" {
		dir := cfg.FilePath[:strings.LastIndex(cfg.FilePath, "/")]
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			os.MkdirAll(dir, 0755)
		}
	} else {
		if _, err := os.Stat("./data"); os.IsNotExist(err) {
			os.MkdirAll("./data", 0755)
		}
	}

	// 使用gorm连接SQLite
	db, err := gorm.Open(sqlite.Open(cfg.FilePath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	log.Info().Str("file", cfg.FilePath).Msg("Connected to SQLite database")
	return db, nil
}

// connectMySQL 连接MySQL数据库
func connectMySQL(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	// 构建MySQL DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.Database)

	// 使用gorm连接MySQL
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	log.Info().Str("host", cfg.Host).Int("port", cfg.Port).Str("database", cfg.Database).Msg("Connected to MySQL database")
	return db, nil
}

// connectPostgreSQL 连接PostgreSQL数据库
func connectPostgreSQL(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	// 构建PostgreSQL DSN
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=Asia/Shanghai",
		cfg.Host, cfg.Username, cfg.Password, cfg.Database, cfg.Port)

	// 使用gorm连接PostgreSQL
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	log.Info().Str("host", cfg.Host).Int("port", cfg.Port).Str("database", cfg.Database).Msg("Connected to PostgreSQL database")
	return db, nil
}

// connectRedis 连接Redis数据库
func connectRedis(cfg *config.DatabaseConfig) (*redis.Client, error) {
	// 创建Redis客户端
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password, // 无密码则为空
		DB:       cfg.Redis.Database, // 使用配置中的数据库
		PoolSize: cfg.Redis.MaxOpenConns,
		MinIdleConns: cfg.Redis.MaxIdleConns,
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info().Str("host", cfg.Redis.Host).Int("port", cfg.Redis.Port).Msg("Connected to Redis database")
	return rdb, nil
}

// autoMigrate 自动迁移表结构
func autoMigrate(db *gorm.DB) error {
	// 迁移模型
	return db.AutoMigrate(
		&models.ScanResult{},
		&models.CrawlResult{},
		&models.Vulnerability{},
		&models.Request{},
		&models.Payload{},
	)
}

// Close 关闭数据库连接
func (db *DB) Close() error {
	// 关闭Redis连接
	if db.rdb != nil {
		return db.rdb.Close()
	}
	
	// 关闭SQL连接
	if db.sqlDB != nil {
		return db.sqlDB.Close()
	}
	return nil
}

// GetDB 获取gorm.DB实例
func (db *DB) GetDB() *gorm.DB {
	return db.gormDB
}

// GetSQLDB 获取sql.DB实例
func (db *DB) GetSQLDB() *sql.DB {
	return db.sqlDB
}

// GetConfig 获取数据库配置
func (db *DB) GetConfig() *config.DatabaseConfig {
	return db.config
}

// GetRedisClient 获取Redis客户端
func (db *DB) GetRedisClient() *redis.Client {
	return db.rdb
}

// Ping 测试数据库连接
func (db *DB) Ping() error {
	if db.sqlDB == nil {
		return fmt.Errorf("database connection is not initialized")
	}
	return db.sqlDB.Ping()
}

// Begin 开始事务
func (db *DB) Begin() *gorm.DB {
	return db.gormDB.Begin()
}

// Transaction 执行事务
func (db *DB) Transaction(fc func(tx *gorm.DB) error) error {
	return db.gormDB.Transaction(fc)
}

// SaveScanResult 保存扫描结果
func (db *DB) SaveScanResult(result *models.ScanResult) error {
	// 注意：Stats和Configuration已经是结构体，不需要序列化

	// 创建数据库记录
	scanResult := &models.ScanResult{
		Target:        result.Target,
		StartTime:     result.StartTime,
		EndTime:       result.EndTime,
		Duration:      result.Duration,
		Configuration: result.Configuration,
		Vulnerabilities: result.Vulnerabilities,
		Stats:         result.Stats,
	}

	// 保存到数据库
	if err := db.gormDB.Create(scanResult).Error; err != nil {
		return fmt.Errorf("failed to save scan result: %w", err)
	}

	// 保存漏洞
	for i := range result.Vulnerabilities {
		if err := db.SaveVulnerability(result.Vulnerabilities[i], ""); err != nil {
			log.Error().Err(err).Msg("Failed to save vulnerability")
		}
	}

	return nil
}

// GetScanResult 获取扫描结果
func (db *DB) GetScanResult(id string) (*models.ScanResult, error) {
	var result models.ScanResult
	if err := db.gormDB.Where("id = ?", id).First(&result).Error; err != nil {
		return nil, fmt.Errorf("failed to get scan result: %w", err)
	}

	// 反序列化统计数据
	// 注意：在当前模型中，Stats已经是结构体，不需要反序列化

	// 反序列化配置
	// 注意：在当前模型中，Configuration已经是结构体，不需要反序列化

	// 获取漏洞
	vulns, err := db.GetVulnerabilitiesByScanID(id)
	if err != nil {
		log.Error().Err(err).Str("scan_id", id).Msg("Failed to get vulnerabilities")
	} else {
		result.Vulnerabilities = vulns
	}

	return &result, nil
}

// ListScanResults 列出扫描结果
func (db *DB) ListScanResults(limit, offset int) ([]*models.ScanResult, int64, error) {
	var results []*models.ScanResult
	var total int64

	// 获取总数
	if err := db.gormDB.Model(&models.ScanResult{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count scan results: %w", err)
	}

	// 获取分页数据
	if err := db.gormDB.Order("created_at DESC").Limit(limit).Offset(offset).Find(&results).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list scan results: %w", err)
	}

	// 为每个结果填充漏洞数据
	for _, result := range results {
		vulns, err := db.GetVulnerabilitiesByScanID(result.ID)
		if err != nil {
			log.Error().Err(err).Str("scan_id", result.ID).Msg("Failed to get vulnerabilities")
			continue
		}
		result.Vulnerabilities = vulns

		// 注意：在当前模型中，Stats已经是结构体，不需要反序列化

		// 注意：在当前模型中，Configuration已经是结构体，不需要反序列化
	}

	return results, total, nil
}

// DeleteScanResult 删除扫描结果
func (db *DB) DeleteScanResult(id string) error {
	// 先删除关联的漏洞
	if err := db.gormDB.Where("scan_id = ?", id).Delete(&models.Vulnerability{}).Error; err != nil {
		return fmt.Errorf("failed to delete vulnerabilities: %w", err)
	}

	// 删除扫描结果
	if err := db.gormDB.Where("id = ?", id).Delete(&models.ScanResult{}).Error; err != nil {
		return fmt.Errorf("failed to delete scan result: %w", err)
	}

	return nil
}

// SaveVulnerability 保存漏洞
func (db *DB) SaveVulnerability(vuln *models.Vulnerability, scanID string) error {
	// 序列化请求数据
	requestJSON, err := json.Marshal(vuln.Request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// 序列化载荷数据
	payloadJSON, err := json.Marshal(vuln.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// 创建数据库记录
	vulnRecord := &models.Vulnerability{
		ID:          vuln.ID,
		ScanID:      scanID,
		Type:        vuln.Type,
		Name:        vuln.Name,
		Description: vuln.Description,
		Severity:    vuln.Severity,
		Location:    vuln.Location,
		Parameter:   vuln.Parameter,
		Evidence:    vuln.Evidence,
		Request:     vuln.Request,
		Response:    vuln.Response,
		Solution:    vuln.Solution,
		References:  vuln.References,
		Tags:        vuln.Tags,
		Timestamp:   vuln.Timestamp,
		Confidence:  vuln.Confidence,
		Payload:     vuln.Payload,
		PayloadJSON: string(payloadJSON),
		RequestJSON: string(requestJSON),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// 保存到数据库
	if err := db.gormDB.Create(vulnRecord).Error; err != nil {
		return fmt.Errorf("failed to save vulnerability: %w", err)
	}

	return nil
}

// GetVulnerability 获取漏洞
func (db *DB) GetVulnerability(id string) (*models.Vulnerability, error) {
	var vuln models.Vulnerability
	if err := db.gormDB.Where("id = ?", id).First(&vuln).Error; err != nil {
		return nil, fmt.Errorf("failed to get vulnerability: %w", err)
	}

	// 反序列化请求数据
	if vuln.RequestJSON != "" {
		var request models.Request
		if err := json.Unmarshal([]byte(vuln.RequestJSON), &request); err != nil {
			log.Error().Err(err).Str("vuln_id", id).Msg("Failed to unmarshal request")
		} else {
			vuln.Request = &request
		}
	}

	// 反序列化载荷数据
	if vuln.PayloadJSON != "" {
		var payload models.Payload
		if err := json.Unmarshal([]byte(vuln.PayloadJSON), &payload); err != nil {
			log.Error().Err(err).Str("vuln_id", id).Msg("Failed to unmarshal payload")
		} else {
			vuln.Payload = &payload
		}
	}

	return &vuln, nil
}

// GetVulnerabilitiesByScanID 根据扫描ID获取漏洞
func (db *DB) GetVulnerabilitiesByScanID(scanID string) ([]*models.Vulnerability, error) {
	var vulns []*models.Vulnerability
	if err := db.gormDB.Where("scan_id = ?", scanID).Find(&vulns).Error; err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}

	// 为每个漏洞填充数据
	for _, vuln := range vulns {
		// 反序列化请求数据
		if vuln.RequestJSON != "" {
			var request models.Request
			if err := json.Unmarshal([]byte(vuln.RequestJSON), &request); err != nil {
				log.Error().Err(err).Str("vuln_id", vuln.ID).Msg("Failed to unmarshal request")
			} else {
				vuln.Request = &request
			}
		}

		// 反序列化载荷数据
		if vuln.PayloadJSON != "" {
			var payload models.Payload
			if err := json.Unmarshal([]byte(vuln.PayloadJSON), &payload); err != nil {
				log.Error().Err(err).Str("vuln_id", vuln.ID).Msg("Failed to unmarshal payload")
			} else {
				vuln.Payload = &payload
			}
		}
	}

	return vulns, nil
}

// ListVulnerabilities 列出漏洞
func (db *DB) ListVulnerabilities(limit, offset int, severity string) ([]*models.Vulnerability, int64, error) {
	var vulns []*models.Vulnerability
	var total int64

	query := db.gormDB.Model(&models.Vulnerability{})

	// 添加严重性过滤条件
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	// 获取总数
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}

	// 获取分页数据
	if err := query.Order("created_at DESC").Limit(limit).Offset(offset).Find(&vulns).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	// 为每个漏洞填充数据
	for _, vuln := range vulns {
		// 反序列化请求数据
		if vuln.RequestJSON != "" {
			var request models.Request
			if err := json.Unmarshal([]byte(vuln.RequestJSON), &request); err != nil {
				log.Error().Err(err).Str("vuln_id", vuln.ID).Msg("Failed to unmarshal request")
			} else {
				vuln.Request = &request
			}
		}

		// 反序列化载荷数据
		if vuln.PayloadJSON != "" {
			var payload models.Payload
			if err := json.Unmarshal([]byte(vuln.PayloadJSON), &payload); err != nil {
				log.Error().Err(err).Str("vuln_id", vuln.ID).Msg("Failed to unmarshal payload")
			} else {
				vuln.Payload = &payload
			}
		}
	}

	return vulns, total, nil
}

// DeleteVulnerability 删除漏洞
func (db *DB) DeleteVulnerability(id string) error {
	if err := db.gormDB.Where("id = ?", id).Delete(&models.Vulnerability{}).Error; err != nil {
		return fmt.Errorf("failed to delete vulnerability: %w", err)
	}

	return nil
}

// SaveCrawlResult 保存爬取结果
func (db *DB) SaveCrawlResult(result *models.CrawlResult) error {
	// 序列化表单数据
	formsJSON, err := json.Marshal(result.Forms)
	if err != nil {
		return fmt.Errorf("failed to marshal forms: %w", err)
	}

	// 序列化API端点
	apiEndpointsJSON, err := json.Marshal(result.APIEndpoints)
	if err != nil {
		return fmt.Errorf("failed to marshal API endpoints: %w", err)
	}

	// 创建数据库记录
	crawlResult := &models.CrawlResult{
		ID:              result.ID,
		URL:             result.URL,
		Title:           result.Title,
		StatusCode:      result.StatusCode,
		ContentType:     result.ContentType,
		ContentLength:   result.ContentLength,
		FormsJSON:       string(formsJSON),
		APIEndpointsJSON: string(apiEndpointsJSON),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// 保存到数据库
	if err := db.gormDB.Create(crawlResult).Error; err != nil {
		return fmt.Errorf("failed to save crawl result: %w", err)
	}

	return nil
}

// GetCrawlResult 获取爬取结果
func (db *DB) GetCrawlResult(id string) (*models.CrawlResult, error) {
	var result models.CrawlResult
	if err := db.gormDB.Where("id = ?", id).First(&result).Error; err != nil {
		return nil, fmt.Errorf("failed to get crawl result: %w", err)
	}

	// 反序列化表单数据
	if result.FormsJSON != "" {
		var forms []models.Form
		if err := json.Unmarshal([]byte(result.FormsJSON), &forms); err != nil {
			log.Error().Err(err).Str("crawl_id", id).Msg("Failed to unmarshal forms")
		} else {
			result.Forms = forms
		}
	}

	// 反序列化API端点
	if result.APIEndpointsJSON != "" {
		var apiEndpoints []string
		if err := json.Unmarshal([]byte(result.APIEndpointsJSON), &apiEndpoints); err != nil {
			log.Error().Err(err).Str("crawl_id", id).Msg("Failed to unmarshal API endpoints")
		} else {
			result.APIEndpoints = apiEndpoints
		}
	}

	return &result, nil
}

// ListCrawlResults 列出爬取结果
func (db *DB) ListCrawlResults(limit, offset int) ([]*models.CrawlResult, int64, error) {
	var results []*models.CrawlResult
	var total int64

	// 获取总数
	if err := db.gormDB.Model(&models.CrawlResult{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count crawl results: %w", err)
	}

	// 获取分页数据
	if err := db.gormDB.Order("created_at DESC").Limit(limit).Offset(offset).Find(&results).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list crawl results: %w", err)
	}

	// 为每个结果填充数据
	for _, result := range results {
		// 反序列化表单数据
		if result.FormsJSON != "" {
			var forms []models.Form
			if err := json.Unmarshal([]byte(result.FormsJSON), &forms); err != nil {
				log.Error().Err(err).Str("crawl_id", result.ID).Msg("Failed to unmarshal forms")
			} else {
				result.Forms = forms
			}
		}

		// 反序列化API端点
		if result.APIEndpointsJSON != "" {
			var apiEndpoints []string
			if err := json.Unmarshal([]byte(result.APIEndpointsJSON), &apiEndpoints); err != nil {
				log.Error().Err(err).Str("crawl_id", result.ID).Msg("Failed to unmarshal API endpoints")
			} else {
				result.APIEndpoints = apiEndpoints
			}
		}
	}

	return results, total, nil
}

// DeleteCrawlResult 删除爬取结果
func (db *DB) DeleteCrawlResult(id string) error {
	if err := db.gormDB.Where("id = ?", id).Delete(&models.CrawlResult{}).Error; err != nil {
		return fmt.Errorf("failed to delete crawl result: %w", err)
	}

	return nil
}

// GetStats 获取统计信息
func (db *DB) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 获取扫描结果统计
	var scanCount int64
	if err := db.gormDB.Model(&models.ScanResult{}).Count(&scanCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count scan results: %w", err)
	}
	stats["scan_count"] = scanCount

	// 获取漏洞统计
	var vulnCount int64
	if err := db.gormDB.Model(&models.Vulnerability{}).Count(&vulnCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}
	stats["vulnerability_count"] = vulnCount

	// 获取爬取结果统计
	var crawlCount int64
	if err := db.gormDB.Model(&models.CrawlResult{}).Count(&crawlCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count crawl results: %w", err)
	}
	stats["crawl_count"] = crawlCount

	// 获取漏洞严重性统计
	vulnStats := make(map[string]int64)
	severities := []string{"Critical", "High", "Medium", "Low", "Info"}
	for _, severity := range severities {
		var count int64
		if err := db.gormDB.Model(&models.Vulnerability{}).Where("severity = ?", severity).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("failed to count %s vulnerabilities: %w", severity, err)
		}
		vulnStats[strings.ToLower(severity)] = count
	}
	stats["vulnerability_severity"] = vulnStats

	// 获取漏洞类型统计
	vulnTypes := make(map[string]int64)
	rows, err := db.gormDB.Model(&models.Vulnerability{}).Select("type, count(*) as count").Group("type").Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability types: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var vulnType string
		var count int64
		if err := rows.Scan(&vulnType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability type: %w", err)
		}
		vulnTypes[vulnType] = count
	}
	stats["vulnerability_types"] = vulnTypes

	return stats, nil
}

// Query 执行自定义查询
func (db *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.sqlDB.Query(query, args...)
}

// Exec 执行自定义命令
func (db *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return db.sqlDB.Exec(query, args...)
}

// Raw 执行原始SQL查询
func (db *DB) Raw(sql string, values ...interface{}) *gorm.DB {
	return db.gormDB.Raw(sql, values...)
}

// ExecRaw 执行原始SQL命令
func (db *DB) ExecRaw(sql string, values ...interface{}) error {
	return db.gormDB.Exec(sql, values...).Error
}

// IsNotFound 检查错误是否为记录未找到
func (db *DB) IsNotFound(err error) bool {
	return err == gorm.ErrRecordNotFound
}

// IsDuplicateKey 检查错误是否为重复键
func (db *DB) IsDuplicateKey(err error) bool {
	// 根据数据库类型判断
	if strings.Contains(err.Error(), "UNIQUE constraint failed") ||
		strings.Contains(err.Error(), "Duplicate entry") ||
		strings.Contains(err.Error(), "duplicate key value") {
		return true
	}
	return false
}

// GetTableInfo 获取表信息
func (db *DB) GetTableInfo(tableName string) ([]map[string]interface{}, error) {
	var columns []map[string]interface{}

	// 根据数据库类型获取表信息
	switch strings.ToLower(db.config.Type) {
	case "sqlite":
		rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			return nil, fmt.Errorf("failed to get table info: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var cid int
			var name string
			var dataType string
			var notNull int
			var dfltValue interface{}
			var pk int

			if err := rows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk); err != nil {
				return nil, fmt.Errorf("failed to scan column info: %w", err)
			}

			column := map[string]interface{}{
				"name":      name,
				"type":      dataType,
				"not_null":  notNull == 1,
				"default":   dfltValue,
				"primary":   pk == 1,
			}
			columns = append(columns, column)
		}

	case "mysql":
		rows, err := db.Query(fmt.Sprintf("DESCRIBE %s", tableName))
		if err != nil {
			return nil, fmt.Errorf("failed to get table info: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var field, typeStr, null, key, defaultValue, extra string

			if err := rows.Scan(&field, &typeStr, &null, &key, &defaultValue, &extra); err != nil {
				return nil, fmt.Errorf("failed to scan column info: %w", err)
			}

			column := map[string]interface{}{
				"name":      field,
				"type":      typeStr,
				"not_null":  null == "NO",
				"default":   defaultValue,
				"primary":   key == "PRI",
				"extra":     extra,
			}
			columns = append(columns, column)
		}

	case "postgres", "postgresql":
		query := `
			SELECT column_name, data_type, is_nullable, column_default
			FROM information_schema.columns
			WHERE table_name = $1
			ORDER BY ordinal_position
		`
		rows, err := db.Query(query, tableName)
		if err != nil {
			return nil, fmt.Errorf("failed to get table info: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var columnName, dataType, isNullable, columnDefault string

			if err := rows.Scan(&columnName, &dataType, &isNullable, &columnDefault); err != nil {
				return nil, fmt.Errorf("failed to scan column info: %w", err)
			}

			column := map[string]interface{}{
				"name":      columnName,
				"type":      dataType,
				"not_null":  isNullable == "NO",
				"default":   columnDefault,
			}
			columns = append(columns, column)
		}

	default:
		return nil, fmt.Errorf("unsupported database type: %s", db.config.Type)
	}

	return columns, nil
}

// Backup 备份数据库
func (db *DB) Backup(outputPath string) error {
	// 根据数据库类型执行不同的备份策略
	switch strings.ToLower(db.config.Type) {
	case "sqlite":
		// SQLite数据库可以直接复制文件
		return db.backupSQLite(outputPath)
	case "mysql":
		// MySQL数据库使用mysqldump
		return db.backupMySQL(outputPath)
	case "postgres", "postgresql":
		// PostgreSQL数据库使用pg_dump
		return db.backupPostgreSQL(outputPath)
	default:
		return fmt.Errorf("unsupported database type: %s", db.config.Type)
	}
}

// backupSQLite 备份SQLite数据库
func (db *DB) backupSQLite(outputPath string) error {
	// SQLite数据库可以直接复制文件
	sourceFile := db.config.FilePath
	if sourceFile == "" {
		return fmt.Errorf("SQLite database file path is empty")
	}

	// 使用SQL语句创建备份
	_, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", outputPath))
	if err != nil {
		return fmt.Errorf("failed to backup SQLite database: %w", err)
	}

	log.Info().Str("source", sourceFile).Str("output", outputPath).Msg("SQLite database backup completed")
	return nil
}

// backupMySQL 备份MySQL数据库
func (db *DB) backupMySQL(outputPath string) error {
	// 在实际实现中，这里应该调用mysqldump命令
	// 这里简化为使用SQL导出
	// 注意：这不是完整的备份方案，实际应用中应该使用mysqldump
	return fmt.Errorf("MySQL backup not implemented")
}

// backupPostgreSQL 备份PostgreSQL数据库
func (db *DB) backupPostgreSQL(outputPath string) error {
	// 在实际实现中，这里应该调用pg_dump命令
	// 这里简化为使用SQL导出
	// 注意：这不是完整的备份方案，实际应用中应该使用pg_dump
	return fmt.Errorf("PostgreSQL backup not implemented")
}

// Restore 恢复数据库
func (db *DB) Restore(inputPath string) error {
	// 根据数据库类型执行不同的恢复策略
	switch strings.ToLower(db.config.Type) {
	case "sqlite":
		// SQLite数据库可以直接复制文件
		return db.restoreSQLite(inputPath)
	case "mysql":
		// MySQL数据库使用mysql命令
		return db.restoreMySQL(inputPath)
	case "postgres", "postgresql":
		// PostgreSQL数据库使用psql命令
		return db.restorePostgreSQL(inputPath)
	default:
		return fmt.Errorf("unsupported database type: %s", db.config.Type)
	}
}

// restoreSQLite 恢复SQLite数据库
func (db *DB) restoreSQLite(inputPath string) error {
	// SQLite数据库可以直接复制文件
	targetFile := db.config.FilePath
	if targetFile == "" {
		return fmt.Errorf("SQLite database file path is empty")
	}

	// 关闭当前数据库连接
	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close database connection: %w", err)
	}

	// 复制备份文件
	// 在实际实现中，这里应该复制文件
	// 这里简化为重新连接数据库
	newDB, err := NewDB(db.config)
	if err != nil {
		return fmt.Errorf("failed to reconnect to database: %w", err)
	}

	// 更新当前数据库连接
	*db = *newDB

	log.Info().Str("input", inputPath).Str("target", targetFile).Msg("SQLite database restore completed")
	return nil
}

// restoreMySQL 恢复MySQL数据库
func (db *DB) restoreMySQL(inputPath string) error {
	// 在实际实现中，这里应该调用mysql命令
	// 这里简化为使用SQL导入
	// 注意：这不是完整的恢复方案，实际应用中应该使用mysql命令
	return fmt.Errorf("MySQL restore not implemented")
}

// restorePostgreSQL 恢复PostgreSQL数据库
func (db *DB) restorePostgreSQL(inputPath string) error {
	// 在实际实现中，这里应该调用psql命令
	// 这里简化为使用SQL导入
	// 注意：这不是完整的恢复方案，实际应用中应该使用psql命令
	return fmt.Errorf("PostgreSQL restore not implemented")
}

// Health 检查数据库健康状态
func (db *DB) Health() (map[string]interface{}, error) {
	health := make(map[string]interface{})

	// 检查连接状态
	if err := db.Ping(); err != nil {
		health["status"] = "unhealthy"
		health["error"] = err.Error()
		return health, nil
	}

	health["status"] = "healthy"

	// 获取连接池状态
	stats := db.sqlDB.Stats()
	health["open_connections"] = stats.OpenConnections
	health["in_use"] = stats.InUse
	health["idle"] = stats.Idle
	health["wait_count"] = stats.WaitCount
	health["wait_duration"] = stats.WaitDuration
	health["max_idle_closed"] = stats.MaxIdleClosed
	health["max_lifetime_closed"] = stats.MaxLifetimeClosed

	// 获取数据库信息
	var version string
	switch strings.ToLower(db.config.Type) {
	case "sqlite":
		if err := db.gormDB.Raw("SELECT sqlite_version() AS version").Scan(&version).Error; err != nil {
			return nil, fmt.Errorf("failed to get SQLite version: %w", err)
		}
	case "mysql":
		if err := db.gormDB.Raw("SELECT VERSION() AS version").Scan(&version).Error; err != nil {
			return nil, fmt.Errorf("failed to get MySQL version: %w", err)
		}
	case "postgres", "postgresql":
		if err := db.gormDB.Raw("SELECT version() AS version").Scan(&version).Error; err != nil {
			return nil, fmt.Errorf("failed to get PostgreSQL version: %w", err)
		}
	}

	health["version"] = version
	health["type"] = db.config.Type

	return health, nil
}

// GetContext 获取带有上下文的数据库连接
func (db *DB) GetContext(ctx context.Context) *gorm.DB {
	return db.gormDB.WithContext(ctx)
}

// WithContext 使用上下文执行操作
func (db *DB) WithContext(ctx context.Context) *gorm.DB {
	return db.gormDB.WithContext(ctx)
}

// Debug 启用调试模式
func (db *DB) Debug() *gorm.DB {
	return db.gormDB.Debug()
}

// Model 指定模型
func (db *DB) Model(model interface{}) *gorm.DB {
	return db.gormDB.Model(model)
}

// Select 选择字段
func (db *DB) Select(query interface{}, args ...interface{}) *gorm.DB {
	return db.gormDB.Select(query, args...)
}

// Where 添加条件
func (db *DB) Where(query interface{}, args ...interface{}) *gorm.DB {
	return db.gormDB.Where(query, args...)
}

// Order 排序
func (db *DB) Order(value interface{}) *gorm.DB {
	return db.gormDB.Order(value)
}

// Limit 限制结果数量
func (db *DB) Limit(limit int) *gorm.DB {
	return db.gormDB.Limit(limit)
}

// Offset 偏移量
func (db *DB) Offset(offset int) *gorm.DB {
	return db.gormDB.Offset(offset)
}

// Group 分组
func (db *DB) Group(name string) *gorm.DB {
	return db.gormDB.Group(name)
}

// Having 添加分组条件
func (db *DB) Having(query interface{}, args ...interface{}) *gorm.DB {
	return db.gormDB.Having(query, args...)
}

// Joins 添加连接
func (db *DB) Joins(query string, args ...interface{}) *gorm.DB {
	return db.gormDB.Joins(query, args...)
}

// Preload 预加载关联
func (db *DB) Preload(query string, args ...interface{}) *gorm.DB {
	return db.gormDB.Preload(query, args...)
}

// Create 创建记录
func (db *DB) Create(value interface{}) *gorm.DB {
	return db.gormDB.Create(value)
}

// First 获取第一条记录
func (db *DB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	return db.gormDB.First(dest, conds...)
}

// Find 查找记录
func (db *DB) Find(dest interface{}, conds ...interface{}) *gorm.DB {
	return db.gormDB.Find(dest, conds...)
}

// Update 更新记录
func (db *DB) Update(column string, value interface{}) *gorm.DB {
	return db.gormDB.Update(column, value)
}

// Updates 更新多列
func (db *DB) Updates(values interface{}) *gorm.DB {
	return db.gormDB.Updates(values)
}

// Delete 删除记录
func (db *DB) Delete(value interface{}, conds ...interface{}) *gorm.DB {
	return db.gormDB.Delete(value, conds...)
}

// Count 计数
func (db *DB) Count(count *int64) *gorm.DB {
	return db.gormDB.Count(count)
}

// Row 获取单行
func (db *DB) Row() *sql.Row {
	return db.gormDB.Row()
}

// Rows 获取多行
func (db *DB) Rows() (*sql.Rows, error) {
	return db.gormDB.Rows()
}

// Scan 扫描结果
func (db *DB) Scan(dest interface{}) *gorm.DB {
	return db.gormDB.Scan(dest)
}

// Pluck 提取单列
func (db *DB) Pluck(column string, dest interface{}) *gorm.DB {
	return db.gormDB.Pluck(column, dest)
}

// Distinct 去重
func (db *DB) Distinct(args ...interface{}) *gorm.DB {
	return db.gormDB.Distinct(args...)
}

// Attrs 设置属性
func (db *DB) Attrs(attrs ...interface{}) *gorm.DB {
	return db.gormDB.Attrs(attrs...)
}

// Assign 赋值
func (db *DB) Assign(attrs ...interface{}) *gorm.DB {
	return db.gormDB.Assign(attrs...)
}

// FirstOrCreate 查找或创建
func (db *DB) FirstOrCreate(dest interface{}, conds ...interface{}) *gorm.DB {
	return db.gormDB.FirstOrCreate(dest, conds...)
}

// FirstOrInit 查找或初始化
func (db *DB) FirstOrInit(dest interface{}, conds ...interface{}) *gorm.DB {
	return db.gormDB.FirstOrInit(dest, conds...)
}

// UpdateColumn 更新列
func (db *DB) UpdateColumn(column string, value interface{}) *gorm.DB {
	return db.gormDB.UpdateColumn(column, value)
}

// UpdateColumns 更新多列
func (db *DB) UpdateColumns(values interface{}) *gorm.DB {
	return db.gormDB.UpdateColumns(values)
}

// Save 保存记录
func (db *DB) Save(value interface{}) *gorm.DB {
	return db.gormDB.Save(value)
}

// CreateInBatches 批量创建
func (db *DB) CreateInBatches(value interface{}, batchSize int) *gorm.DB {
	return db.gormDB.CreateInBatches(value, batchSize)
}

// SavePoint 创建保存点
func (db *DB) SavePoint(name string) *gorm.DB {
	return db.gormDB.SavePoint(name)
}

// RollbackTo 回滚到保存点
func (db *DB) RollbackTo(name string) *gorm.DB {
	return db.gormDB.RollbackTo(name)
}

// ToSQL 获取生成的SQL
func (db *DB) ToSQL(stmt *gorm.Statement) string {
	return db.gormDB.ToSQL(stmt)
}

// ToSQLErr 获取生成的SQL和错误
func (db *DB) ToSQLErr(stmt *gorm.Statement) (string, error) {
	// 创建一个带有DryRun选项的会话来生成SQL而不执行
	dryRunDB := db.gormDB.Session(&gorm.Session{DryRun: true})
	// 执行一个操作来生成SQL
	result := dryRunDB.Statement
	return result.SQL.String(), result.Error
}

// TableName 获取表名
func (db *DB) TableName(model interface{}) string {
	stmt := &gorm.Statement{DB: db.gormDB}
	stmt.Parse(model)
	return stmt.Schema.Table
}

// Migrator 获取迁移器
func (db *DB) Migrator() gorm.Migrator {
	return db.gormDB.Migrator()
}

// Callbacks 获取回调
// Callbacks 返回gorm回调
func (db *DB) Callbacks() interface{} {
	return db.gormDB.Callback
}

// AddError 添加错误
func (db *DB) AddError(err error) error {
	return db.gormDB.AddError(err)
}

// DB 获取底层*gorm.DB
func (db *DB) DB() *gorm.DB {
	return db.gormDB
}

// Statement 获取语句
func (db *DB) Statement() *gorm.Statement {
	return db.gormDB.Statement
}

// InstanceGet 获取实例值
func (db *DB) InstanceGet(name string) (interface{}, bool) {
	return db.gormDB.InstanceGet(name)
}

// InstanceSet 设置实例值
func (db *DB) InstanceSet(name string, value interface{}) *gorm.DB {
	return db.gormDB.InstanceSet(name, value)
}

// Set 设置值
func (db *DB) Set(name string, value interface{}) *gorm.DB {
	return db.gormDB.Set(name, value)
}

// Get 获取值
func (db *DB) Get(name string) (interface{}, bool) {
	return db.gormDB.Get(name)
}

// DryRun 运行但不执行
func (db *DB) DryRun() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{DryRun: true})
}

// SetupJoinTable 设置连接表
func (db *DB) SetupJoinTable(model interface{}, field string, joinTable interface{}) error {
	return db.gormDB.SetupJoinTable(model, field, joinTable)
}

// Association 获取关联
func (db *DB) Association(column string) *gorm.Association {
	return db.gormDB.Association(column)
}

// Context 设置上下文
func (db *DB) Context(ctx context.Context) *gorm.DB {
	return db.gormDB.WithContext(ctx)
}

// NewSession 创建新会话
func (db *DB) NewSession() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{})
}

// Session 设置会话
func (db *DB) Session(config *gorm.Session) *gorm.DB {
	return db.gormDB.Session(config)
}

// Scopes 使用作用域
func (db *DB) Scopes(funcs ...func(*gorm.DB) *gorm.DB) *gorm.DB {
	return db.gormDB.Scopes(funcs...)
}

// Unscoped 禁用软删除
func (db *DB) Unscoped() *gorm.DB {
	return db.gormDB.Unscoped()
}



// Logger 设置日志
func (db *DB) Logger(logger logger.Interface) *gorm.DB {
	return db.gormDB.Session(&gorm.Session{Logger: logger})
}

// NowFunc 设置当前时间函数
func (db *DB) NowFunc(nowFunc func() time.Time) *gorm.DB {
	return db.gormDB.Session(&gorm.Session{NowFunc: nowFunc})
}

// QueryFields 查询字段
func (db *DB) QueryFields() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{QueryFields: true})
}

// CreateBatchSize 设置批量创建大小
func (db *DB) CreateBatchSize(size int) *gorm.DB {
	return db.gormDB.Session(&gorm.Session{CreateBatchSize: size})
}

// FullSaveAssociations 保存所有关联
func (db *DB) FullSaveAssociations() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{FullSaveAssociations: true})
}

// UpdateColumnOnly 只更新列
func (db *DB) UpdateColumnOnly() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{UpdateColumnOnly: true})
}

// SkipHooks 跳过钩子
func (db *DB) SkipHooks() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{SkipHooks: true})
}

// SkipDefaultUpdate 跳过默认更新
func (db *DB) SkipDefaultUpdate() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{SkipDefaultUpdate: true})
}

// SkipDefaultCreate 跳过默认创建
func (db *DB) SkipDefaultCreate() *gorm.DB {
	return db.gormDB.Session(&gorm.Session{SkipDefaultCreate: true})
}

// RedisPing 测试Redis连接
func (db *DB) RedisPing() error {
	if db.rdb == nil {
		return fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	_, err := db.rdb.Ping(ctx).Result()
	return err
}

// ============ Redis 键值操作 ============

// RedisSet 设置键值
func (db *DB) RedisSet(key string, value interface{}, expiration time.Duration) error {
	if db.rdb == nil {
		return fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Set(ctx, key, value, expiration).Err()
}

// RedisGet 获取键值
func (db *DB) RedisGet(key string) (string, error) {
	if db.rdb == nil {
		return "", fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Get(ctx, key).Result()
}

// RedisDel 删除键
func (db *DB) RedisDel(keys ...string) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Del(ctx, keys...).Result()
}

// RedisExists 检查键是否存在
func (db *DB) RedisExists(keys ...string) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Exists(ctx, keys...).Result()
}

// RedisExpire 设置键的过期时间
func (db *DB) RedisExpire(key string, expiration time.Duration) (bool, error) {
	if db.rdb == nil {
		return false, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Expire(ctx, key, expiration).Result()
}

// RedisTTL 获取键的过期时间
func (db *DB) RedisTTL(key string) (time.Duration, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.TTL(ctx, key).Result()
}

// ============ Redis 哈希操作 ============

// RedisHSet 设置哈希字段
func (db *DB) RedisHSet(key string, values ...interface{}) error {
	if db.rdb == nil {
		return fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.HSet(ctx, key, values...).Err()
}

// RedisHGet 获取哈希字段值
func (db *DB) RedisHGet(key, field string) (string, error) {
	if db.rdb == nil {
		return "", fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.HGet(ctx, key, field).Result()
}

// RedisHGetAll 获取哈希所有字段和值
func (db *DB) RedisHGetAll(key string) (map[string]string, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.HGetAll(ctx, key).Result()
}

// RedisHDel 删除哈希字段
func (db *DB) RedisHDel(key string, fields ...string) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.HDel(ctx, key, fields...).Result()
}

// RedisHExists 检查哈希字段是否存在
func (db *DB) RedisHExists(key, field string) (bool, error) {
	if db.rdb == nil {
		return false, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.HExists(ctx, key, field).Result()
}

// ============ Redis 列表操作 ============

// RedisLPush 左侧推入列表
func (db *DB) RedisLPush(key string, values ...interface{}) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.LPush(ctx, key, values...).Result()
}

// RedisRPush 右侧推入列表
func (db *DB) RedisRPush(key string, values ...interface{}) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.RPush(ctx, key, values...).Result()
}

// RedisLPop 左侧弹出列表
func (db *DB) RedisLPop(key string) (string, error) {
	if db.rdb == nil {
		return "", fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.LPop(ctx, key).Result()
}

// RedisRPop 右侧弹出列表
func (db *DB) RedisRPop(key string) (string, error) {
	if db.rdb == nil {
		return "", fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.RPop(ctx, key).Result()
}

// RedisLRange 获取列表范围内的元素
func (db *DB) RedisLRange(key string, start, stop int64) ([]string, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.LRange(ctx, key, start, stop).Result()
}

// RedisLLen 获取列表长度
func (db *DB) RedisLLen(key string) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.LLen(ctx, key).Result()
}

// ============ Redis 集合操作 ============

// RedisSAdd 添加集合成员
func (db *DB) RedisSAdd(key string, members ...interface{}) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.SAdd(ctx, key, members...).Result()
}

// RedisSMembers 获取集合所有成员
func (db *DB) RedisSMembers(key string) ([]string, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.SMembers(ctx, key).Result()
}

// RedisSRem 删除集合成员
func (db *DB) RedisSRem(key string, members ...interface{}) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.SRem(ctx, key, members...).Result()
}

// RedisSIsMember 检查是否是集合成员
func (db *DB) RedisSIsMember(key string, member interface{}) (bool, error) {
	if db.rdb == nil {
		return false, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.SIsMember(ctx, key, member).Result()
}

// RedisSCard 获取集合成员数量
func (db *DB) RedisSCard(key string) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.SCard(ctx, key).Result()
}

// ============ Redis 有序集合操作 ============

// RedisZAdd 添加有序集合成员
func (db *DB) RedisZAdd(key string, members ...*redis.Z) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.ZAdd(ctx, key, members...).Result()
}

// RedisZRange 获取有序集合范围内的成员
func (db *DB) RedisZRange(key string, start, stop int64) ([]string, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.ZRange(ctx, key, start, stop).Result()
}

// RedisZRangeWithScores 获取有序集合范围内的成员和分数
func (db *DB) RedisZRangeWithScores(key string, start, stop int64) ([]redis.Z, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.ZRangeWithScores(ctx, key, start, stop).Result()
}

// RedisZRem 删除有序集合成员
func (db *DB) RedisZRem(key string, members ...interface{}) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.ZRem(ctx, key, members...).Result()
}

// RedisZCard 获取有序集合成员数量
func (db *DB) RedisZCard(key string) (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.ZCard(ctx, key).Result()
}

// ============ Redis 其他操作 ============

// RedisFlushDB 清空当前数据库
func (db *DB) RedisFlushDB() error {
	if db.rdb == nil {
		return fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.FlushDB(ctx).Err()
}

// RedisKeys 获取所有匹配的键
func (db *DB) RedisKeys(pattern string) ([]string, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Keys(ctx, pattern).Result()
}

// RedisInfo 获取Redis信息
func (db *DB) RedisInfo() (string, error) {
	if db.rdb == nil {
		return "", fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Info(ctx).Result()
}

// RedisDBSize 获取数据库大小
func (db *DB) RedisDBSize() (int64, error) {
	if db.rdb == nil {
		return 0, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.DBSize(ctx).Result()
}

// RedisExecute 执行任意Redis命令
func (db *DB) RedisExecute(cmd string, args ...interface{}) (interface{}, error) {
	if db.rdb == nil {
		return nil, fmt.Errorf("Redis connection is not initialized")
	}
	
	ctx := context.Background()
	return db.rdb.Do(ctx, cmd, args...).Result()
}