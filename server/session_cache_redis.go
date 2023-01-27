package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
	"go.uber.org/zap"
	"time"
)

const baseKeyStructure = "brs::nakama::%s::%s"

var namespaceUser = "user"

type RedisSessionCache struct {
	config         Config
	logger         *zap.Logger
	client         *redis.Client
	isRedisWorking bool
	backupCache    SessionCache
}

func NewRedisSessionCache(logger *zap.Logger, config Config) SessionCache {
	cacheConfig := config.GetCache()

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

	var isRedisWorking bool
	redisClient := redis.NewClient(rbdOptions)
	if redisClient == nil {
		logger.Info("SessionCache: Redis client not properly connected. Using local cache")
		isRedisWorking = false
	} else if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		logger.Info("SessionCache: Redis client not properly connected. Using local cache", zap.Error(err))
		isRedisWorking = false
	} else {
		logger.Info("SessionCache: Redis connection established.")
		isRedisWorking = true
	}

	if !isRedisWorking {
		return &RedisSessionCache{
			config:         config,
			logger:         logger,
			client:         nil,
			isRedisWorking: false,
			backupCache:    NewLocalSessionCache(config),
		}
	}

	namespaceUser = fmt.Sprintf(baseKeyStructure, cacheConfig.CacheName, namespaceUser)

	return &RedisSessionCache{
		config:         config,
		logger:         logger,
		client:         redisClient,
		isRedisWorking: true,
	}
}

func (s *RedisSessionCache) Stop() {
	if !s.isRedisWorking {
		s.backupCache.Stop()
		return
	}

	s.client.Close()
}

func (s *RedisSessionCache) IsValidSession(userID uuid.UUID, exp int64, token string) bool {
	if !s.isRedisWorking {
		return s.backupCache.IsValidSession(userID, exp, token)
	}

	cachedUser := s.Get(userID)
	if cachedUser == nil {
		return false
	}

	return cachedUser.SessionExp >= time.Now().UTC().Unix()
}

func (s *RedisSessionCache) IsValidRefresh(userID uuid.UUID, exp int64, token string) bool {
	if !s.isRedisWorking {
		return s.backupCache.IsValidRefresh(userID, exp, token)
	}

	cachedUser := s.Get(userID)
	if cachedUser == nil {
		return false
	}

	return cachedUser.RefreshExp >= time.Now().UTC().Unix()
}

func (s *RedisSessionCache) Add(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	if !s.isRedisWorking {
		s.backupCache.Add(userID, sessionExp, sessionToken, refreshExp, refreshToken)
		return
	}

	cachedUser := CachedUser{
		UserId:       userID.String(),
		SessionExp:   sessionExp,
		SessionToken: sessionToken,
		RefreshExp:   refreshExp,
		RefreshToken: refreshToken,
	}

	data, err := json.Marshal(cachedUser)
	if err != nil {
		s.logger.Error("SessionCache: Error marshalling cachedUser. User won't be added to cache", zap.Error(err), zap.String("userId", userID.String()))
		return
	}

	maxTime := refreshExp
	if sessionExp > refreshExp {
		maxTime = sessionExp
	}

	deletionTime := time.Unix(maxTime, 0)
	key := getUserKey(userID)
	if err = s.client.Set(context.Background(), key, data, deletionTime.Sub(time.Now().UTC())).Err(); err != nil {
		s.logger.Error("SessionCache: Error adding user to cache.", zap.Error(err), zap.String("userId", userID.String()))
		return
	}

	s.logger.Debug("SessionCache: User successfully cached.", zap.String("userId", userID.String()), zap.String("json", string(data)))
}

func (s *RedisSessionCache) Get(userID uuid.UUID) *CachedUser {
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

func (s *RedisSessionCache) Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	if !s.isRedisWorking {
		s.backupCache.Remove(userID, sessionExp, sessionToken, refreshExp, refreshToken)
		return
	}

	key := getUserKey(userID)

	if err := s.client.Del(context.Background(), key).Err(); err != nil {
		s.logger.Error("SessionCache: Error adding user to cache.", zap.Error(err), zap.String("userId", userID.String()))
		return
	}

	s.logger.Debug("SessionCache: User deleted from cache.", zap.String("userId", userID.String()))
}

func (s *RedisSessionCache) RemoveAll(userID uuid.UUID) {
	if !s.isRedisWorking {
		s.backupCache.RemoveAll(userID)
		return
	}

	s.Remove(userID, 0, "", 0, "")
}

func (s *RedisSessionCache) Ban(userIDs []uuid.UUID) {
	if !s.isRedisWorking {
		s.backupCache.Ban(userIDs)
		return
	}

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

func (s *RedisSessionCache) Unban(userIDs []uuid.UUID) {}

// CachedUser is used to serialize/deserialize the user stored in cache
type CachedUser struct {
	UserId       string `json:"user_id"`
	SessionExp   int64  `json:"session_exp"`
	SessionToken string `json:"session_token"`
	RefreshExp   int64  `json:"refresh_exp"`
	RefreshToken string `json:"refresh_token"`
}

// getUserKey given a userId returns the corresponding key to be use in cache
func getUserKey(userId uuid.UUID) string {
	return fmt.Sprintf("%s::%s", namespaceUser, userId)
}
