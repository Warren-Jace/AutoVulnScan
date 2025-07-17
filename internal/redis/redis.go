package redis

import (
	"context"
	"github.com/go-redis/redis/v8"
)

// Client is a wrapper around the go-redis client.
type Client struct {
	*redis.Client
}

// NewClient creates and tests a new Redis client.
func NewClient(ctx context.Context, addr string) (*Client, error) {
	opt, err := redis.ParseURL(addr)
	if err != nil {
		return nil, err
	}

	rdb := redis.NewClient(opt)

	// Ping the server to ensure connection is alive.
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &Client{rdb}, nil
} 