export const filterCategories = (categories, searchTerm) => {
    if (!searchTerm.trim()) {
        return categories;
    }

    const search = searchTerm.toLowerCase();
    return categories.filter((category) =>
        category.name.toLowerCase().includes(search)
    );
};

export const getInitialCategoryForm = () => ({
    name: "",
});

export const getInitialLineForm = () => ({
    line: "",
});

export const formatCategoryForEdit = (category) => ({
    name: category.name || "",
});

export const formatLineForEdit = (line) => ({
    line: line.line || "",
});
