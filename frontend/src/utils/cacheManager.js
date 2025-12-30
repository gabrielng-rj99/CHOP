/*
 * This file is part of Client Hub Open Project.
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Cache Manager
 * Provides a robust caching system with TTL (Time To Live) and invalidation support
 */

class CacheManager {
    constructor() {
        this.cache = new Map();
        this.timestamps = new Map();
        this.defaultTTL = 5 * 60 * 1000; // 5 minutes default TTL
    }

    /**
     * Generate a cache key from endpoint and params
     */
    generateKey(endpoint, params = {}) {
        const sortedParams = Object.keys(params)
            .sort()
            .map((key) => `${key}=${JSON.stringify(params[key])}`)
            .join("&");
        return `${endpoint}${sortedParams ? "?" + sortedParams : ""}`;
    }

    /**
     * Check if cache entry is still valid
     */
    isValid(key, ttl = this.defaultTTL) {
        if (!this.cache.has(key)) {
            return false;
        }

        const timestamp = this.timestamps.get(key);
        if (!timestamp) {
            return false;
        }

        const now = Date.now();
        const age = now - timestamp;

        return age < ttl;
    }

    /**
     * Get cached data if valid
     */
    get(key, ttl = this.defaultTTL) {
        if (this.isValid(key, ttl)) {
            return this.cache.get(key);
        }
        return null;
    }

    /**
     * Set cache data
     */
    set(key, data) {
        this.cache.set(key, data);
        this.timestamps.set(key, Date.now());
    }

    /**
     * Invalidate specific cache entry
     */
    invalidate(key) {
        this.cache.delete(key);
        this.timestamps.delete(key);
    }

    /**
     * Invalidate all cache entries matching a pattern
     */
    invalidatePattern(pattern) {
        const regex = new RegExp(pattern);
        const keysToDelete = [];

        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                keysToDelete.push(key);
            }
        }

        keysToDelete.forEach((key) => {
            this.cache.delete(key);
            this.timestamps.delete(key);
        });

        return keysToDelete.length;
    }

    /**
     * Invalidate all entries for a specific resource type
     */
    invalidateResource(resource) {
        return this.invalidatePattern(`^/api/${resource}`);
    }

    /**
     * Clear all cache
     */
    clearAll() {
        this.cache.clear();
        this.timestamps.clear();
    }

    /**
     * Get cache statistics
     */
    getStats() {
        return {
            entries: this.cache.size,
            keys: Array.from(this.cache.keys()),
        };
    }

    /**
     * Clean up expired entries
     */
    cleanup(ttl = this.defaultTTL) {
        const now = Date.now();
        const keysToDelete = [];

        for (const [key, timestamp] of this.timestamps.entries()) {
            if (now - timestamp >= ttl) {
                keysToDelete.push(key);
            }
        }

        keysToDelete.forEach((key) => {
            this.cache.delete(key);
            this.timestamps.delete(key);
        });

        return keysToDelete.length;
    }
}

// Create singleton instance
const cacheManager = new CacheManager();

// Run cleanup every 10 minutes
setInterval(
    () => {
        cacheManager.cleanup();
    },
    10 * 60 * 1000,
);

export default cacheManager;
