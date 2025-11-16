const usersApi = {
    loadUsers: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/api/users`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao carregar usuários");
        }

        const data = await response.json();
        return data.data || [];
    },

    createUser: async (apiUrl, token, userData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/api/users`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(userData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar usuário");
        }

        return await response.json();
    },

    updateUser: async (apiUrl, token, username, userData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/api/users/${username}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(userData),
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar usuário");
        }

        return await response.json();
    },

    blockUser: async (apiUrl, token, username, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/api/users/${username}/block`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao bloquear usuário");
        }

        return await response.json();
    },

    unlockUser: async (apiUrl, token, username, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/api/users/${username}/unlock`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao desbloquear usuário");
        }

        return await response.json();
    },

    deleteUser: async (apiUrl, token, username, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/api/users/${username}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        if (response.status === 401) {
            onTokenExpired?.();
            throw new Error("Token inválido ou expirado. Faça login novamente.");
        }

        if (!response.ok) {
            throw new Error("Erro ao deletar usuário");
        }

        return await response.json();
    },
};

export { usersApi };
