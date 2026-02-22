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

import { handleResponseErrors } from "./apiHelpers";

const usersApi = {
    loadUsers: async (apiUrl, token, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/users`, {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao carregar usuários");
        }

        const data = await response.json();
        return data.data || [];
    },

    createUser: async (apiUrl, token, userData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/users`, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(userData),
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao criar usuário");
        }

        return await response.json();
    },

    updateUser: async (apiUrl, token, username, userData, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/users/${username}`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(userData),
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || "Erro ao atualizar usuário");
        }

        return await response.json();
    },

    blockUser: async (apiUrl, token, username, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/users/${username}/block`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao bloquear usuário");
        }

        return await response.json();
    },

    unlockUser: async (apiUrl, token, username, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/users/${username}/unlock`, {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao desbloquear usuário");
        }

        return await response.json();
    },

    deleteUser: async (apiUrl, token, username, onTokenExpired) => {
        const response = await fetch(`${apiUrl}/users/${username}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });

        handleResponseErrors(response, onTokenExpired);

        if (!response.ok) {
            throw new Error("Erro ao deletar usuário");
        }

        return await response.json();
    },
};

export { usersApi };
