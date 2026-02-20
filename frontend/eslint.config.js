import reactHooks from "eslint-plugin-react-hooks";

export default [
    {
        files: ["**/*.{js,jsx}"],
        plugins: {
            "react-hooks": reactHooks,
        },
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "module",
            parserOptions: {
                ecmaFeatures: {
                    jsx: true,
                },
            },
        },
        rules: {
            "react-hooks/rules-of-hooks": "off",
            "react-hooks/exhaustive-deps": "off",
            "react-hooks/set-state-in-effect": "off",
            "react-hooks/globals": "off",
            "react-hooks/immutability": "off",
        },
    },
];
