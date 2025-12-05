/*
 * This file is part of Entity Hub Open Project.
 * Copyright (C) 2025 Entity Hub Contributors
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

export const filterUsers = (users, searchTerm) => {
    if (!searchTerm.trim()) {
        return users;
    }

    const search = searchTerm.toLowerCase();
    return users.filter(
        (user) =>
            user.username?.toLowerCase().includes(search) ||
            user.display_name?.toLowerCase().includes(search) ||
            user.role?.toLowerCase().includes(search),
    );
};

export const getInitialFormData = () => ({
    username: "",
    display_name: "",
    password: "",
    role: "user",
});

export const formatUserForEdit = (user) => ({
    username: user.username || "",
    display_name: user.display_name || "",
    password: "",
    role: user.role || "user",
});

export const getRoleName = (role) => {
    const roles = {
        admin: "Administrador",
        user: "Usuário",
    };
    return roles[role] || role;
};

export const formatDate = (dateString) => {
    if (!dateString) return "-";
    // Parse date correctly to avoid timezone issues
    if (dateString.match(/^\d{4}-\d{2}-\d{2}/)) {
        const [datePart, timePart] = dateString.split("T");
        const [year, month, day] = datePart.split("-");
        if (timePart) {
            const [hour, minute] = timePart.split(":");
            return `${day}/${month}/${year} ${hour}:${minute}`;
        }
        return `${day}/${month}/${year}`;
    }
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
};
