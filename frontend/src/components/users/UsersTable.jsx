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

import React from "react";
import { getRoleName, formatDate } from "../../utils/userHelpers";
import "./UsersTable.css";
import EditIcon from "../../assets/icons/edit.svg";
import LockIcon from "../../assets/icons/lock.svg";
import UnlockIcon from "../../assets/icons/unlock.svg";
import TrashIcon from "../../assets/icons/trash.svg";

export default function UsersTable({
    filteredUsers,
    currentUser,
    onEdit,
    onBlock,
    onUnlock,
    onDelete,
}) {
    if (filteredUsers.length === 0) {
        return (
            <div className="users-table-empty">
                <p>Nenhum usuário encontrado</p>
            </div>
        );
    }

    return (
        <table className="users-table">
            <thead>
                <tr>
                    <th>Nome de Exibição</th>
                    <th>Nome de Usuário</th>
                    <th>Função</th>
                    <th className="status">Status</th>
                    <th className="actions">Ações</th>
                </tr>
            </thead>
            <tbody>
                {filteredUsers.map((user) => {
                    const isBlocked = user.lock_level >= 3;
                    const isCurrentUser =
                        user.username === currentUser?.username;

                    return (
                        <tr
                            key={user.username}
                            className={isBlocked ? "blocked" : ""}
                        >
                            <td>{user.display_name || "-"}</td>
                            <td>
                                {user.username}
                                {isCurrentUser && (
                                    <span className="users-table-current-badge">
                                        VOCÊ
                                    </span>
                                )}
                            </td>
                            <td>
                                <span
                                    className={`users-table-role ${
                                        user.role === "root"
                                            ? "root"
                                            : user.role === "admin"
                                              ? "admin"
                                              : "user"
                                    }`}
                                >
                                    {getRoleName(user.role)}
                                </span>
                            </td>
                            <td className="status">
                                <span
                                    className={`users-table-status ${
                                        isBlocked ? "blocked" : "active"
                                    }`}
                                >
                                    {isBlocked ? "Bloqueado" : "Ativo"}
                                </span>
                            </td>
                            <td className="actions">
                                <div className="users-table-actions">
                                    <button
                                        onClick={() => onEdit(user)}
                                        className="users-table-icon-button"
                                        title="Editar"
                                    >
                                        <img
                                            src={EditIcon}
                                            alt="Editar"
                                            style={{
                                                width: "22px",
                                                height: "22px",
                                                filter: "invert(44%) sepia(92%) saturate(1092%) hue-rotate(182deg) brightness(95%) contrast(88%)",
                                            }}
                                        />
                                    </button>
                                    {!isCurrentUser && (
                                        <>
                                            {isBlocked ? (
                                                <button
                                                    onClick={() =>
                                                        onUnlock(user.username)
                                                    }
                                                    className="users-table-icon-button"
                                                    title="Desbloquear"
                                                >
                                                    <img
                                                        src={UnlockIcon}
                                                        alt="Desbloquear"
                                                        style={{
                                                            width: "22px",
                                                            height: "22px",
                                                            filter: "invert(62%) sepia(34%) saturate(760%) hue-rotate(88deg) brightness(93%) contrast(81%)",
                                                        }}
                                                    />
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={() =>
                                                        onBlock(user.username)
                                                    }
                                                    className="users-table-icon-button"
                                                    title="Bloquear"
                                                >
                                                    <img
                                                        src={LockIcon}
                                                        alt="Bloquear"
                                                        style={{
                                                            width: "22px",
                                                            height: "22px",
                                                            filter: "invert(57%) sepia(74%) saturate(449%) hue-rotate(359deg) brightness(96%) contrast(89%)",
                                                        }}
                                                    />
                                                </button>
                                            )}
                                            <button
                                                onClick={() =>
                                                    onDelete(user.username)
                                                }
                                                className="users-table-icon-button"
                                                title="Deletar"
                                            >
                                                <img
                                                    src={TrashIcon}
                                                    alt="Deletar"
                                                    style={{
                                                        width: "22px",
                                                        height: "22px",
                                                        filter: "invert(37%) sepia(93%) saturate(1447%) hue-rotate(342deg) brightness(94%) contrast(88%)",
                                                    }}
                                                />
                                            </button>
                                        </>
                                    )}
                                </div>
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}
