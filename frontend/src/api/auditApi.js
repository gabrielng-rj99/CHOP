export const auditApi = {
    // Get audit logs with filters and pagination
    getAuditLogs: async (apiUrl, token, filters = {}, onTokenExpired) => {
        const params = new URLSearchParams();

        if (filters.entity) params.append("entity", filters.entity);
        if (filters.operation) params.append("operation", filters.operation);
        if (filters.adminId) params.append("admin_id", filters.adminId);
        if (filters.adminSearch)
            params.append("admin_search", filters.adminSearch);
        if (filters.entityId) params.append("entity_id", filters.entityId);
        if (filters.entitySearch)
            params.append("entity_search", filters.entitySearch);
        if (filters.changedData)
            params.append("changed_data", filters.changedData);
        if (filters.status) params.append("status", filters.status);
        if (filters.ipAddress) params.append("ip_address", filters.ipAddress);
        if (filters.startDate) params.append("start_date", filters.startDate);
        if (filters.endDate) params.append("end_date", filters.endDate);
        if (filters.limit) params.append("limit", filters.limit);
        if (filters.offset) params.append("offset", filters.offset);

        const response = await fetch(
            `${apiUrl}/audit-logs?${params.toString()}`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || "Erro ao carregar logs");
        }

        return await response.json();
    },

    // Get a specific audit log by ID
    getAuditLogDetail: async (apiUrl, token, logId, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/audit-logs/${logId}`, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || "Erro ao carregar log de auditoria");
        }

        return await response.json();
    },

    // Get all audit logs for a specific entity
    getAuditLogsByEntity: async (
        apiUrl,
        token,
        entity,
        entityId,
        limit = 100,
        offset = 0,
        onTokenExpired,
    ) => {
        const params = new URLSearchParams();
        params.append("limit", limit);
        params.append("offset", offset);

        const response = await fetch(
            `${apiUrl}/audit-logs/entity/${entityType}/${entityId}?${params.toString()}`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || "Erro ao carregar logs");
        }

        return await response.json();
    },

    // Export audit logs as JSON
    exportAuditLogs: async (apiUrl, token, filters = {}, onTokenExpired) => {
        const params = new URLSearchParams();

        if (filters.entity) params.append("entity", filters.entity);
        if (filters.operation) params.append("operation", filters.operation);
        if (filters.adminId) params.append("admin_id", filters.adminId);
        if (filters.adminSearch)
            params.append("admin_search", filters.adminSearch);
        if (filters.entitySearch)
            params.append("entity_search", filters.entitySearch);
        if (filters.changedData)
            params.append("changed_data", filters.changedData);

        const response = await fetch(
            `${apiUrl}/audit-logs/export?${params.toString()}`,
            {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
            },
        );

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error(
                "Token inválido ou expirado. Faça login novamente.",
            );
        }

        if (!response.ok) {
            throw new Error("Erro ao exportar logs");
        }

        return await response.json();
    },
};
