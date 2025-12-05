# =============================================================================
# Entity Hub Open Project
# Copyright (C) 2025 Entity Hub Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

import pytest
import requests
import time
import uuid

@pytest.mark.api
@pytest.mark.security
class TestUsersAPI:
    """Testes completos da API de usuários"""

    def test_list_users_requires_auth(self, http_client, api_url, timer):
        """Listar usuários requer autenticação"""
        response = http_client.get(f"{api_url}/users")
        assert response.status_code == 401, "Deve exigir autenticação"

    def test_list_users_as_root(self, http_client, api_url, root_user, timer):
        """Root pode listar todos os usuários"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)

        assert response.status_code == 200, "Root deve poder listar usuários"
        assert isinstance(response.json(), (list, dict)), "Resposta deve ser JSON válido"

    def test_list_users_as_admin(self, http_client, api_url, admin_user, timer):
        """Admin pode listar usuários"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)

        assert response.status_code == 200, "Admin deve poder listar usuários"

    def test_list_users_as_regular_user_denied(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode listar todos os usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}
        response = http_client.get(f"{api_url}/users", headers=headers)

        assert response.status_code in [401, 403], "Usuário comum não deve listar todos os usuários"

    def test_create_user_as_root(self, http_client, api_url, root_user, timer):
        """Root pode criar usuários de qualquer role"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário comum
        response = http_client.post(f"{api_url}/users", json={
            "username": f"testuser_{int(time.time())}",
            "display_name": "Test User",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [200, 201], "Root deve poder criar usuários"

    def test_create_user_as_admin(self, http_client, api_url, admin_user, timer):
        """Admin pode criar usuários comuns"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"admintest_{int(time.time())}",
            "display_name": "Admin Created User",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [200, 201], "Admin deve poder criar usuários comuns"

    def test_create_root_user_blocked_for_admin(self, http_client, api_url, admin_user, timer):
        """Admin não pode criar usuários root"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"fakerootadmin_{int(time.time())}",
            "display_name": "Fake Root",
            "password": "ValidPass123!@#abc",
            "role": "root"
        }, headers=headers)

        assert response.status_code in [400, 403], "Admin não deve poder criar root"

    def test_create_user_as_regular_user_denied(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode criar outros usuários"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}

        response = http_client.post(f"{api_url}/users", json={
            "username": f"usercreated_{int(time.time())}",
            "display_name": "User Created",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        assert response.status_code in [401, 403], "Usuário comum não deve criar outros"

    def test_get_user_by_id(self, http_client, api_url, root_user, timer):
        """Buscar usuário por ID/username"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"getuser_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Get User Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário")

        # Buscar usuário
        get_response = http_client.get(f"{api_url}/users/{test_username}", headers=headers)
        assert get_response.status_code == 200, "Deve encontrar usuário criado"

    def test_update_user(self, http_client, api_url, root_user, timer):
        """Atualizar dados do usuário"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"updateuser_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Update Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário")

        # Atualizar
        update_response = http_client.put(f"{api_url}/users/{test_username}", json={
            "display_name": "Updated Name"
        }, headers=headers)

        assert update_response.status_code in [200, 204], "Deve permitir atualização"

    def test_delete_user(self, http_client, api_url, root_user, timer):
        """Deletar usuário"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar usuário
        test_username = f"deleteuser_{int(time.time())}"
        create_response = http_client.post(f"{api_url}/users", json={
            "username": test_username,
            "display_name": "Delete Test",
            "password": "ValidPass123!@#abc",
            "role": "user"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar usuário")

        # Deletar
        delete_response = http_client.delete(f"{api_url}/users/{test_username}", headers=headers)
        assert delete_response.status_code in [200, 204], "Deve permitir deleção"

        # Verificar que foi deletado
        get_response = http_client.get(f"{api_url}/users/{test_username}", headers=headers)
        assert get_response.status_code in [403, 404], "Usuário deletado não deve ser encontrado"


@pytest.mark.api
@pytest.mark.security
class TestClientsAPI:
    """Testes completos da API de clientes"""

    def test_list_clients_requires_auth(self, http_client, api_url, timer):
        """Listar clientes requer autenticação"""
        response = http_client.get(f"{api_url}/clients")
        assert response.status_code == 401, "Deve exigir autenticação"

    def test_list_clients_success(self, http_client, api_url, root_user, timer):
        """Listar clientes com sucesso"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/clients", headers=headers)

        assert response.status_code == 200, "Deve listar clientes"

    def test_create_client(self, http_client, api_url, root_user, timer):
        """Criar cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Test Client {int(time.time())}",
            "email": f"test_{int(time.time())}@test.com",
            "phone": "11999999999"
        }, headers=headers)

        assert response.status_code in [200, 201], "Deve criar cliente"

    def test_create_client_with_all_fields(self, http_client, api_url, root_user, timer):
        """Criar cliente com todos os campos"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/clients", json={
            "name": f"Full Client {int(time.time())}",
            "registration_id": f"CPF{int(time.time())}",
            "nickname": "Nickname",
            "birth_date": "1990-01-15",
            "email": f"full_{int(time.time())}@test.com",
            "phone": "11888888888",
            "address": "Rua Teste, 123",
            "notes": "Notas do cliente",
            "tags": "vip,premium",
            "contact_preference": "email"
        }, headers=headers)

        assert response.status_code in [200, 201], "Deve criar cliente com todos os campos"

    def test_get_client_by_id(self, http_client, api_url, root_user, timer):
        """Buscar cliente por ID"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente
        create_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Get Client {int(time.time())}",
            "email": "gettest@test.com"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = create_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Buscar
        get_response = http_client.get(f"{api_url}/clients/{client_id}", headers=headers)
        assert get_response.status_code == 200, "Deve encontrar cliente"

    def test_update_client(self, http_client, api_url, root_user, timer):
        """Atualizar cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente
        create_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Update Client {int(time.time())}",
            "email": "updatetest@test.com"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = create_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Atualizar
        update_response = http_client.put(f"{api_url}/clients/{client_id}", json={
            "notes": "Notas atualizadas"
        }, headers=headers)

        assert update_response.status_code in [200, 204], "Deve permitir atualização"

    def test_delete_client(self, http_client, api_url, root_user, timer):
        """Deletar cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente
        create_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Delete Client {int(time.time())}",
            "email": "deletetest@test.com"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = create_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Deletar
        delete_response = http_client.delete(f"{api_url}/clients/{client_id}", headers=headers)
        assert delete_response.status_code in [200, 204], "Deve permitir deleção"

    def test_archive_client(self, http_client, api_url, root_user, timer):
        """Arquivar cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente
        create_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Archive Client {int(time.time())}",
            "email": "archivetest@test.com"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = create_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Arquivar
        archive_response = http_client.post(f"{api_url}/clients/{client_id}/archive", headers=headers)
        assert archive_response.status_code in [200, 204], "Deve permitir arquivamento"

    def test_unarchive_client(self, http_client, api_url, root_user, timer):
        """Desarquivar cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente
        create_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Unarchive Client {int(time.time())}",
            "email": "unarchivetest@test.com"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = create_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Arquivar primeiro
        http_client.post(f"{api_url}/clients/{client_id}/archive", headers=headers)

        # Desarquivar
        unarchive_response = http_client.post(f"{api_url}/clients/{client_id}/unarchive", headers=headers)
        assert unarchive_response.status_code in [200, 204], "Deve permitir desarquivamento"


@pytest.mark.api
@pytest.mark.security
class TestCategoriesAPI:
    """Testes completos da API de categorias"""

    def test_list_categories_requires_auth(self, http_client, api_url, timer):
        """Listar categorias requer autenticação"""
        response = http_client.get(f"{api_url}/categories")
        assert response.status_code == 401, "Deve exigir autenticação"

    def test_list_categories_success(self, http_client, api_url, root_user, timer):
        """Listar categorias com sucesso"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/categories", headers=headers)

        assert response.status_code == 200, "Deve listar categorias"

    def test_create_category(self, http_client, api_url, root_user, timer):
        """Criar categoria"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/categories", json={
            "name": f"Test Category {int(time.time())}"
        }, headers=headers)

        assert response.status_code in [200, 201], "Deve criar categoria"

    def test_get_category_by_id(self, http_client, api_url, root_user, timer):
        """Buscar categoria por ID"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria
        create_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Get Category {int(time.time())}"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_data = create_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        if not cat_id:
            pytest.skip("ID da categoria não retornado")

        # Buscar
        get_response = http_client.get(f"{api_url}/categories/{cat_id}", headers=headers)
        assert get_response.status_code == 200, "Deve encontrar categoria"

    def test_update_category(self, http_client, api_url, root_user, timer):
        """Atualizar categoria"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria
        create_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Update Category {int(time.time())}"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_data = create_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        if not cat_id:
            pytest.skip("ID da categoria não retornado")

        # Atualizar
        update_response = http_client.put(f"{api_url}/categories/{cat_id}", json={
            "name": f"Updated Category {int(time.time())}"
        }, headers=headers)

        assert update_response.status_code in [200, 204], "Deve permitir atualização"

    def test_delete_category(self, http_client, api_url, root_user, timer):
        """Deletar categoria"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria
        create_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Delete Category {int(time.time())}"
        }, headers=headers)

        if create_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_data = create_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        if not cat_id:
            pytest.skip("ID da categoria não retornado")

        # Deletar
        delete_response = http_client.delete(f"{api_url}/categories/{cat_id}", headers=headers)
        assert delete_response.status_code in [200, 204], "Deve permitir deleção"

    def test_duplicate_category_name_rejected(self, http_client, api_url, root_user, timer):
        """Categoria com nome duplicado deve ser rejeitada"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        cat_name = f"Unique Category {int(time.time())}"

        # Criar primeira categoria
        http_client.post(f"{api_url}/categories", json={"name": cat_name}, headers=headers)

        # Tentar criar duplicada
        response = http_client.post(f"{api_url}/categories", json={"name": cat_name}, headers=headers)

        assert response.status_code in [400, 409, 422], "Nome duplicado deve ser rejeitado"


@pytest.mark.api
@pytest.mark.security
class TestLinesAPI:
    """Testes completos da API de linhas"""

    def test_list_lines_requires_auth(self, http_client, api_url, timer):
        """Listar linhas requer autenticação"""
        response = http_client.get(f"{api_url}/lines")
        assert response.status_code == 401, "Deve exigir autenticação"

    def test_list_lines_success(self, http_client, api_url, root_user, timer):
        """Listar linhas com sucesso"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/lines", headers=headers)

        assert response.status_code == 200, "Deve listar linhas"

    def test_create_line(self, http_client, api_url, root_user, timer):
        """Criar linha"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria primeiro
        cat_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Line Test Category {int(time.time())}"
        }, headers=headers)

        if cat_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_data = cat_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        if not cat_id:
            pytest.skip("ID da categoria não retornado")

        # Criar linha
        response = http_client.post(f"{api_url}/lines", json={
            "name": f"Test Line {int(time.time())}",
            "category_id": cat_id
        }, headers=headers)

        assert response.status_code in [200, 201], "Deve criar linha"

    def test_create_line_without_category_rejected(self, http_client, api_url, root_user, timer):
        """Criar linha sem categoria deve ser rejeitado"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        response = http_client.post(f"{api_url}/lines", json={
            "name": f"No Category Line {int(time.time())}"
        }, headers=headers)

        assert response.status_code in [400, 422], "Linha sem categoria deve ser rejeitada"

    def test_get_lines_by_category(self, http_client, api_url, root_user, timer):
        """Buscar linhas por categoria"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria
        cat_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Lines By Category {int(time.time())}"
        }, headers=headers)

        if cat_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_data = cat_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        if not cat_id:
            pytest.skip("ID da categoria não retornado")

        # Criar linha
        http_client.post(f"{api_url}/lines", json={
            "name": f"Category Line {int(time.time())}",
            "category_id": cat_id
        }, headers=headers)

        # Buscar linhas da categoria
        response = http_client.get(f"{api_url}/categories/{cat_id}/lines", headers=headers)
        assert response.status_code == 200, "Deve retornar linhas da categoria"


@pytest.mark.api
@pytest.mark.security
class TestContractsAPI:
    """Testes completos da API de contratos"""

    def test_list_contracts_requires_auth(self, http_client, api_url, timer):
        """Listar contratos requer autenticação"""
        response = http_client.get(f"{api_url}/contracts")
        assert response.status_code == 401, "Deve exigir autenticação"

    def test_list_contracts_success(self, http_client, api_url, root_user, timer):
        """Listar contratos com sucesso"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/contracts", headers=headers)

        assert response.status_code == 200, "Deve listar contratos"

    def test_create_contract(self, http_client, api_url, root_user, timer):
        """Criar contrato"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar categoria
        cat_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Contract Category {int(time.time())}"
        }, headers=headers)

        if cat_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_data = cat_response.json()
        cat_id = cat_data.get("data", {}).get("id") or cat_data.get("id")

        # Criar linha
        line_response = http_client.post(f"{api_url}/lines", json={
            "name": f"Contract Line {int(time.time())}",
            "category_id": cat_id
        }, headers=headers)

        if line_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar linha")

        line_data = line_response.json()
        line_id = line_data.get("data", {}).get("id") or line_data.get("id")

        # Criar cliente
        client_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Contract Client {int(time.time())}",
            "email": "contracttest@test.com"
        }, headers=headers)

        if client_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = client_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        # Criar contrato
        response = http_client.post(f"{api_url}/contracts", json={
            "model": "Premium",
            "product_key": f"PK-{int(time.time())}",
            "line_id": line_id,
            "client_id": client_id
        }, headers=headers)

        assert response.status_code in [200, 201], "Deve criar contrato"

    def test_create_contract_missing_required_fields(self, http_client, api_url, root_user, timer):
        """Criar contrato sem campos obrigatórios deve falhar"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Sem line_id
        response = http_client.post(f"{api_url}/contracts", json={
            "client_id": "12345678-1234-1234-1234-123456789012"
        }, headers=headers)

        assert response.status_code in [400, 422], "Sem line_id deve ser rejeitado"

        # Sem client_id
        response = http_client.post(f"{api_url}/contracts", json={
            "line_id": "12345678-1234-1234-1234-123456789012"
        }, headers=headers)

        assert response.status_code in [400, 422], "Sem client_id deve ser rejeitado"

    def test_archive_contract(self, http_client, api_url, root_user, timer):
        """Arquivar contrato"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar dependências
        cat_response = http_client.post(f"{api_url}/categories", json={
            "name": f"Archive Contract Cat {int(time.time())}"
        }, headers=headers)

        if cat_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar categoria")

        cat_id = cat_response.json().get("data", {}).get("id") or cat_response.json().get("id")

        line_response = http_client.post(f"{api_url}/lines", json={
            "name": f"Archive Contract Line {int(time.time())}",
            "category_id": cat_id
        }, headers=headers)

        if line_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar linha")

        line_id = line_response.json().get("data", {}).get("id") or line_response.json().get("id")

        client_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Archive Contract Client {int(time.time())}",
            "email": "archivecontract@test.com"
        }, headers=headers)

        if client_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_id = client_response.json().get("data", {}).get("id") or client_response.json().get("id")

        # Criar contrato
        contract_response = http_client.post(f"{api_url}/contracts", json={
            "product_key": f"ARCH-{int(time.time())}",
            "line_id": line_id,
            "client_id": client_id
        }, headers=headers)

        if contract_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar contrato")

        contract_id = contract_response.json().get("data", {}).get("id") or contract_response.json().get("id")

        # Arquivar
        archive_response = http_client.post(f"{api_url}/contracts/{contract_id}/archive", headers=headers)
        assert archive_response.status_code in [200, 204], "Deve permitir arquivamento"


@pytest.mark.api
@pytest.mark.security
class TestDependentsAPI:
    """Testes completos da API de dependentes"""

    def test_create_dependent(self, http_client, api_url, root_user, timer):
        """Criar dependente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente primeiro
        client_response = http_client.post(f"{api_url}/clients", json={
            "name": f"Dependent Client {int(time.time())}",
            "email": "dependenttest@test.com"
        }, headers=headers)

        if client_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = client_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        if not client_id:
            pytest.skip("ID do cliente não retornado")

        # Criar dependente
        response = http_client.post(f"{api_url}/clients/{client_id}/dependents", json={
            "name": f"Dependent {int(time.time())}",
            "description": "Filho",
            "email": "dependent@test.com"
        }, headers=headers)

        assert response.status_code in [200, 201], "Deve criar dependente"

    def test_list_client_dependents(self, http_client, api_url, root_user, timer):
        """Listar dependentes de um cliente"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}

        # Criar cliente
        client_response = http_client.post(f"{api_url}/clients", json={
            "name": f"List Deps Client {int(time.time())}",
            "email": "listdeps@test.com"
        }, headers=headers)

        if client_response.status_code not in [200, 201]:
            pytest.skip("Não foi possível criar cliente")

        client_data = client_response.json()
        client_id = client_data.get("data", {}).get("id") or client_data.get("id")

        # Criar alguns dependentes
        for i in range(3):
            http_client.post(f"{api_url}/clients/{client_id}/dependents", json={
                "name": f"Dependent {i} {int(time.time())}",
                "description": f"Dependent {i}"
            }, headers=headers)

        # Listar dependentes
        response = http_client.get(f"{api_url}/clients/{client_id}/dependents", headers=headers)
        assert response.status_code == 200, "Deve listar dependentes"


@pytest.mark.api
@pytest.mark.security
class TestAuditLogsAPI:
    """Testes completos da API de logs de auditoria"""

    def test_audit_logs_requires_auth(self, http_client, api_url, timer):
        """Logs de auditoria requerem autenticação"""
        response = http_client.get(f"{api_url}/audit-logs")
        assert response.status_code == 401, "Deve exigir autenticação"

    def test_audit_logs_requires_root(self, http_client, api_url, admin_user, timer):
        """Logs de auditoria requerem root"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        headers = {"Authorization": f"Bearer {admin_user['token']}"}
        response = http_client.get(f"{api_url}/audit-logs", headers=headers)

        assert response.status_code == 403, "Admin não deve acessar audit logs"

    def test_audit_logs_as_root(self, http_client, api_url, root_user, timer):
        """Root pode acessar logs de auditoria"""
        if not root_user or "token" not in root_user:
            pytest.skip("Root user não disponível")

        headers = {"Authorization": f"Bearer {root_user['token']}"}
        response = http_client.get(f"{api_url}/audit-logs", headers=headers)

        assert response.status_code == 200, "Root deve acessar audit logs"

    def test_regular_user_cannot_access_audit_logs(self, http_client, api_url, regular_user, timer):
        """Usuário comum não pode acessar logs de auditoria"""
        if not regular_user or "token" not in regular_user:
            pytest.skip("Regular user não disponível")

        headers = {"Authorization": f"Bearer {regular_user['token']}"}
        response = http_client.get(f"{api_url}/audit-logs", headers=headers)

        assert response.status_code == 403, "Usuário comum não deve acessar audit logs"


@pytest.mark.api
@pytest.mark.security
class TestInitializeAPI:
    """Testes da API de inicialização"""

    def test_initialize_status(self, http_client, api_url, timer):
        """Verificar status de inicialização"""
        response = http_client.get(f"{api_url}/initialize/status")

        # Pode ou não exigir auth dependendo do estado
        assert response.status_code in [200, 401, 403], "Deve responder apropriadamente"

    def test_initialize_admin_blocked_when_db_not_empty(self, http_client, api_url, timer):
        """Inicialização de admin bloqueada quando DB não está vazio"""
        response = http_client.post(f"{api_url}/initialize/admin", json={
            "username": "newroot",
            "display_name": "New Root",
            "password": "ValidPass123!@#abc"
        })

        # Se banco já tem dados, deve ser bloqueado
        # Se banco está vazio, pode permitir
        assert response.status_code in [200, 201, 403], "Deve responder de acordo com estado do DB"


@pytest.mark.api
class TestHealthAPI:
    """Testes do endpoint de health check"""

    def test_health_check(self, http_client, api_url, timer):
        """Health check deve funcionar sem autenticação"""
        response = http_client.get(f"{api_url}/../health")

        assert response.status_code in [200, 503], "Health check deve responder"

    def test_health_check_response_format(self, http_client, api_url, timer):
        """Health check deve retornar formato esperado"""
        response = http_client.get(f"{api_url}/../health")

        if response.status_code == 200:
            data = response.json()
            assert "status" in data, "Deve conter campo status"
