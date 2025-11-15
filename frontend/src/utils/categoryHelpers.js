export const filterCategories = (categories, searchTerm, allLines) => {
    if (!searchTerm.trim()) {
        return categories;
    }

    const search = searchTerm.toLowerCase();
    return categories.filter((category) => {
        // Search by category name
        if (category.name.toLowerCase().includes(search)) {
            return true;
        }

        // Search by line names if allLines is provided
        if (allLines && Array.isArray(allLines)) {
            const categoryLines = allLines.filter(
                (line) => line.category_id === category.id,
            );
            return categoryLines.some(
                (line) => line.line && line.line.toLowerCase().includes(search),
            );
        }

        return false;
    });
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
