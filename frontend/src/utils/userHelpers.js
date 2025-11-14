export const filterUsers = (users, searchTerm) => {
    if (!searchTerm.trim()) {
        return users;
    }

    const search = searchTerm.toLowerCase();
    return users.filter((user) =>
        user.username?.toLowerCase().includes(search) ||
        user.display_name?.toLowerCase().includes(search) ||
        user.role?.toLowerCase().includes(search)
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
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
};
