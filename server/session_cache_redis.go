package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
	"go.uber.org/zap"
	"time"
)

const baseKeyStructure = "brs::nakama::%s::%s"

var namespaceUser = "user"

type RedisSessionCache struct {
	config      Config
	logger      *zap.Logger
	client      *redis.Client
	backupCache SessionCache
}

// NewRedisSessionCache returns a new SessionCache that uses Redis to cache sessions.
// It uses config values to connect to Redis and returns errors if connection fails.
func NewRedisSessionCache(logger *zap.Logger, config Config) (SessionCache, error) {
	cacheConfig := config.GetCache()

	if len(cacheConfig.CacheName) == 0 || len(cacheConfig.Address) == 0 {
		return nil, errors.New("redis session cache: not configured")
	}

	rbdOptions := &redis.Options{
		Addr:     cacheConfig.Address,
		Password: cacheConfig.Password,
		DB:       0,
	}

	if cacheConfig.EnableTls {
		rbdOptions.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	redisClient := redis.NewClient(rbdOptions)
	if redisClient == nil {
		logger.Error("SessionCache: Not able to get Redis client")
		return nil, errors.New("redis session cache: not able to get redis connection")
	} else if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		logger.Error("SessionCache: Redis client not properly connected", zap.Error(err))
		return nil, errors.New("redis session cache: not able to ping redis")
	} else {
		logger.Info("SessionCache: Redis connection established.")
	}

	namespaceUser = fmt.Sprintf(baseKeyStructure, cacheConfig.CacheName, namespaceUser)

	return &RedisSessionCache{
		config: config,
		logger: logger,
		client: redisClient,
	}, nil
}

// Stop is called by Nakama when gracefully shutdown is requested
func (s *RedisSessionCache) Stop() {
	s.client.Close()
}

// IsValidSession validates the session token of a user.
func (s *RedisSessionCache) IsValidSession(userID uuid.UUID, expSeconds int64, token string) bool {
	cachedUser := s.getCachedUser(userID)
	if cachedUser == nil {
		return false
	}

	return cachedUser.SessionToken == token && cachedUser.SessionTokenExpSeconds >= time.Now().UTC().Unix()
}

// IsValidRefresh validates the refresh token of a user.
func (s *RedisSessionCache) IsValidRefresh(userID uuid.UUID, expSeconds int64, token string) bool {
	cachedUser := s.getCachedUser(userID)
	if cachedUser == nil {
		return false
	}

	return cachedUser.RefreshToken == token && cachedUser.RefreshTokenExpSeconds >= time.Now().UTC().Unix()
}

// Add is used when a user should be added to session cache.
func (s *RedisSessionCache) Add(userID uuid.UUID, sessionTokenExpirationSeconds int64, sessionToken string, refreshTokenExpirationSeconds int64, refreshToken string) {
	cachedUser := CachedUser{
		UserId:                 userID.String(),
		SessionTokenExpSeconds: sessionTokenExpirationSeconds,
		SessionToken:           sessionToken,
		RefreshTokenExpSeconds: refreshTokenExpirationSeconds,
		RefreshToken:           refreshToken,
	}

	data, err := json.Marshal(cachedUser)
	if err != nil {
		s.logger.Error("SessionCache: Error marshalling cachedUser. User won't be added to cache", zap.Error(err), zap.String("userId", userID.String()))
		return
	}

	maxTime := refreshTokenExpirationSeconds
	if sessionTokenExpirationSeconds > refreshTokenExpirationSeconds {
		maxTime = sessionTokenExpirationSeconds
	}

	deletionTime := time.Unix(maxTime, 0)
	key := getUserKey(userID)
	if err = s.client.Set(context.Background(), key, data, deletionTime.Sub(time.Now().UTC())).Err(); err != nil {
		s.logger.Error("SessionCache: Error adding user to cache.", zap.Error(err), zap.String("userId", userID.String()))
		return
	}

	s.logger.Debug("SessionCache: User successfully cached.", zap.String("userId", userID.String()), zap.String("json", string(data)))
}

// getCachedUser returns cached info of a userId
func (s *RedisSessionCache) getCachedUser(userID uuid.UUID) *CachedUser {
	serializedUser, err := s.client.Get(context.Background(), getUserKey(userID)).Bytes()
	if err != nil {
		s.logger.Error("SessionCache: Error getting user from cache.", zap.Error(err), zap.String("userId", userID.String()))
		return nil
	}

	var cachedUser CachedUser
	if err = json.Unmarshal(serializedUser, &cachedUser); err != nil {
		s.logger.Error("SessionCache: Error deserializing user from cache.", zap.Error(err), zap.String("userId", userID.String()))
		return nil
	}

	return &cachedUser
}

// Remove is used when a user should be removed from the session cache.
func (s *RedisSessionCache) Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	key := getUserKey(userID)

	if err := s.client.Del(context.Background(), key).Err(); err != nil {
		s.logger.Error("SessionCache: Error adding user to cache.", zap.Error(err), zap.String("userId", userID.String()))
		return
	}

	s.logger.Debug("SessionCache: User deleted from cache.", zap.String("userId", userID.String()))
}

// RemoveAll removes all cached info of a userId.
func (s *RedisSessionCache) RemoveAll(userID uuid.UUID) {
	s.Remove(userID, 0, "", 0, "")
}

// Ban is called when a user should be banned, so removed from the cache
func (s *RedisSessionCache) Ban(userIDs []uuid.UUID) {
	userKeys := make([]string, len(userIDs))
	for i := 0; i < len(userIDs); i++ {
		userKeys[i] = getUserKey(userIDs[i])
	}

	if err := s.client.Del(context.Background(), userKeys...).Err(); err != nil {
		s.logger.Error("SessionCache: Error removing user from cache.", zap.Error(err))
		return
	}

	s.logger.Debug("SessionCache: Users banned in cache.", zap.Strings("userIDs", userKeys))
}

// Unban is called when a user should be unbanned from the cache
func (s *RedisSessionCache) Unban(userIDs []uuid.UUID) {}

// CachedUser is used to serialize/deserialize the user stored in cache
type CachedUser struct {
	UserId                 string `json:"user_id"`
	SessionTokenExpSeconds int64  `json:"session_token_exp_sec"`
	SessionToken           string `json:"session_token"`
	RefreshTokenExpSeconds int64  `json:"refresh_token_exp_sec"`
	RefreshToken           string `json:"refresh_token"`
}

// getUserKey given a userId returns the corresponding key to be use in cache
func getUserKey(userId uuid.UUID) string {
	return fmt.Sprintf("%s::%s", namespaceUser, userId)
}
