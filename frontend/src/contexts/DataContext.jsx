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

import React, {
    createContext,
    useContext,
    useState,
    useCallback,
    useRef,
} from "react";
import cacheManager from "../utils/cacheManager";

const DataContext = createContext();

export const useData = () => {
    const context = useContext(DataContext);
    if (!context) {
        throw new Error("useData must be used within a DataProvider");
    }
    return context;
};

export const DataProvider = ({ children, token, apiUrl, onTokenExpired }) => {
    const [loading, setLoading] = useState({});
    const [errors, setErrors] = useState({});
    const requestInProgressRef = useRef(new Map());

    /**
     * Generic fetch with cache support
     */
    const fetchWithCache = useCallback(
        async (
            endpoint,
            options = {},
            cacheKey = null,
            ttl = 5 * 60 * 1000,
            forceRefresh = false,
        ) => {
            const key =
                cacheKey || cacheManager.generateKey(endpoint, options.params);

            // Check if there's already a request in progress for this key
            if (requestInProgressRef.current.has(key)) {
                return requestInProgressRef.current.get(key);
            }

            // Check cache first (unless force refresh)
            if (!forceRefresh) {
                const cachedData = cacheManager.get(key, ttl);
                if (cachedData !== null) {
                    return cachedData;
                }
            }

            // Create the fetch promise
            const fetchPromise = (async () => {
                try {
                    setLoading((prev) => ({ ...prev, [key]: true }));
                    setErrors((prev) => ({ ...prev, [key]: null }));

                    const headers = {
                        Authorization: `Bearer ${token}`,
                        "Content-Type": "application/json",
                        ...options.headers,
                    };

                    const url = new URL(`${apiUrl}${endpoint}`);
                    if (options.params) {
                        Object.keys(options.params).forEach((key) =>
                            url.searchParams.append(key, options.params[key]),
                        );
                    }

                    const response = await fetch(url.toString(), {
                        ...options,
                        headers,
                    });

                    // Check for 401 (token expired)
                    if (response.status === 401) {
                        onTokenExpired?.();
                        throw new Error(
                            "Token inválido ou expirado. Faça login novamente.",
                        );
                    }

                    // Check for 429 (rate limit)
                    if (response.status === 429) {
                        throw new Error(
                            "Muitas requisições. Por favor, aguarde um momento.",
                        );
                    }

                    if (!response.ok) {
                        throw new Error(
                            `Erro ao carregar dados: ${response.statusText}`,
                        );
                    }

                    const data = await response.json();

                    // Cache the response
                    cacheManager.set(key, data);

                    return data;
                } catch (error) {
                    setErrors((prev) => ({ ...prev, [key]: error.message }));
                    throw error;
                } finally {
                    setLoading((prev) => ({ ...prev, [key]: false }));
                    requestInProgressRef.current.delete(key);
                }
            })();

            // Store the promise so duplicate requests can use it
            requestInProgressRef.current.set(key, fetchPromise);

            return fetchPromise;
        },
        [token, apiUrl, onTokenExpired],
    );

    /**
     * Fetch contracts
     */
    const fetchContracts = useCallback(
        async (params = {}, forceRefresh = false) => {
            return fetchWithCache(
                "/contracts",
                { params },
                null,
                5 * 60 * 1000,
                forceRefresh,
            );
        },
        [fetchWithCache],
    );

    /**
     * Fetch clients
     */
    const fetchClients = useCallback(
        async (params = {}, forceRefresh = false) => {
            return fetchWithCache(
                "/clients",
                { params },
                null,
                5 * 60 * 1000,
                forceRefresh,
            );
        },
        [fetchWithCache],
    );

    /**
     * Fetch categories
     */
    const fetchCategories = useCallback(
        async (forceRefresh = false) => {
            return fetchWithCache(
                "/categories",
                {},
                null,
                5 * 60 * 1000,
                forceRefresh,
            );
        },
        [fetchWithCache],
    );

    /**
     * Fetch subcategories for a category
     */
    const fetchSubcategories = useCallback(
        async (categoryId, forceRefresh = false) => {
            return fetchWithCache(
                `/categories/${categoryId}/subcategories`,
                {},
                null,
                5 * 60 * 1000,
                forceRefresh,
            );
        },
        [fetchWithCache],
    );

    /**
     * Create/Update operations that invalidate cache
     */
    const createContract = useCallback(
        async (data) => {
            const response = await fetchWithCache(
                "/contracts",
                {
                    method: "POST",
                    body: JSON.stringify(data),
                },
                null,
                0,
                true,
            );

            // Invalidate contracts cache
            cacheManager.invalidateResource("contracts");

            return response;
        },
        [fetchWithCache],
    );

    const updateContract = useCallback(
        async (id, data) => {
            const response = await fetchWithCache(
                `/contracts/${id}`,
                {
                    method: "PUT",
                    body: JSON.stringify(data),
                },
                null,
                0,
                true,
            );

            // Invalidate contracts cache
            cacheManager.invalidateResource("contracts");

            return response;
        },
        [fetchWithCache],
    );

    const deleteContract = useCallback(
        async (id) => {
            const response = await fetchWithCache(
                `/contracts/${id}`,
                {
                    method: "DELETE",
                },
                null,
                0,
                true,
            );

            // Invalidate contracts cache
            cacheManager.invalidateResource("contracts");

            return response;
        },
        [fetchWithCache],
    );

    const createClient = useCallback(
        async (data) => {
            const response = await fetchWithCache(
                "/clients",
                {
                    method: "POST",
                    body: JSON.stringify(data),
                },
                null,
                0,
                true,
            );

            // Invalidate clients cache
            cacheManager.invalidateResource("clients");

            return response;
        },
        [fetchWithCache],
    );

    const updateClient = useCallback(
        async (id, data) => {
            const response = await fetchWithCache(
                `/clients/${id}`,
                {
                    method: "PUT",
                    body: JSON.stringify(data),
                },
                null,
                0,
                true,
            );

            // Invalidate clients cache
            cacheManager.invalidateResource("clients");

            return response;
        },
        [fetchWithCache],
    );

    const deleteClient = useCallback(
        async (id) => {
            const response = await fetchWithCache(
                `/clients/${id}`,
                {
                    method: "DELETE",
                },
                null,
                0,
                true,
            );

            // Invalidate clients cache
            cacheManager.invalidateResource("clients");

            return response;
        },
        [fetchWithCache],
    );

    const createCategory = useCallback(
        async (data) => {
            const response = await fetchWithCache(
                "/categories",
                {
                    method: "POST",
                    body: JSON.stringify(data),
                },
                null,
                0,
                true,
            );

            // Invalidate categories cache
            cacheManager.invalidateResource("categories");

            return response;
        },
        [fetchWithCache],
    );

    const updateCategory = useCallback(
        async (id, data) => {
            const response = await fetchWithCache(
                `/categories/${id}`,
                {
                    method: "PUT",
                    body: JSON.stringify(data),
                },
                null,
                0,
                true,
            );

            // Invalidate categories cache
            cacheManager.invalidateResource("categories");

            return response;
        },
        [fetchWithCache],
    );

    const deleteCategory = useCallback(
        async (id) => {
            const response = await fetchWithCache(
                `/categories/${id}`,
                {
                    method: "DELETE",
                },
                null,
                0,
                true,
            );

            // Invalidate categories cache
            cacheManager.invalidateResource("categories");

            return response;
        },
        [fetchWithCache],
    );

    /**
     * Manual cache invalidation
     */
    const invalidateCache = useCallback((resource) => {
        if (resource) {
            cacheManager.invalidateResource(resource);
        } else {
            cacheManager.clearAll();
        }
    }, []);

    /**
     * Get cache stats
     */
    const getCacheStats = useCallback(() => {
        return cacheManager.getStats();
    }, []);

    const value = {
        // Fetch methods
        fetchContracts,
        fetchClients,
        fetchCategories,
        fetchSubcategories,
        fetchWithCache,

        // Create/Update/Delete methods
        createContract,
        updateContract,
        deleteContract,
        createClient,
        updateClient,
        deleteClient,
        createCategory,
        updateCategory,
        deleteCategory,

        // Cache management
        invalidateCache,
        getCacheStats,

        // State
        loading,
        errors,
    };

    return (
        <DataContext.Provider value={value}>{children}</DataContext.Provider>
    );
};
