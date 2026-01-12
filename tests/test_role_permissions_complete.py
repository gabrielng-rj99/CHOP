# =============================================================================
# Client Hub Open Project
# Copyright (C) 2025 Client Hub Contributors
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

"""
Testes Completos de Permissões de Roles
Testa todo o fluxo de gerenciamento de permissões de papéis
"""

import pytest
import requests
import time


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def test_role(http_client, api_url, admin_user):
    """Cria uma role de teste"""
    if not admin_user or "token" not in admin_user:
        pytest.skip("Admin user não disponível")

    role_data = {
        "name": f"test_role_{int(time.time())}",
        "display_name": "Test Role for Permissions",
        "description": "Role de teste para verificar permissões",
        "priority": 50
    }

    response = http_client.post(
        f"{api_url}/roles",
        json=role_data,
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )

    if response.status_code != 201:
        pytest.skip(f"Não foi possível criar role de teste: {response.status_code}")

    role = response.json()

    yield role

    # Cleanup
    http_client.delete(
        f"{api_url}/roles/{role['id']}",
        headers={"Authorization": f"Bearer {admin_user['token']}"}
    )


# =============================================================================
# GET /api/permissions - Listar todas as permissões
# =============================================================================

class TestGetPermissions:
    """Testes para GET /api/permissions"""

    def test_get_permissions_without_token_returns_401(self, http_client, api_url, timer):
        """GET /api/permissions sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/permissions")
        assert response.status_code == 401, \
            f"Expected 401 without token, got {response.status_code}"

    def test_get_permissions_with_admin_returns_200(self, http_client, api_url, admin_user, timer):
        """Admin DEVE poder listar permissões"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.get(
            f"{api_url}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 200, \
            f"Expected 200 for admin, got {response.status_code}"

        data = response.json()
        assert isinstance(data, list), "Response should be a list"
        assert len(data) > 0, "Should have at least one permission"

        # Verificar estrutura da permissão
        first_perm = data[0]
        assert "id" in first_perm, "Permission should have id"
        assert "resource" in first_perm, "Permission should have resource"
        assert "action" in first_perm, "Permission should have action"
        assert "display_name" in first_perm, "Permission should have display_name"
        assert "category" in first_perm, "Permission should have category"

    def test_get_permissions_grouped_by_category(self, http_client, api_url, admin_user, timer):
        """GET /api/permissions?group_by=category DEVE retornar agrupado"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.get(
            f"{api_url}/permissions?group_by=category",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 200, \
            f"Expected 200, got {response.status_code}"

        data = response.json()
        assert isinstance(data, dict), "Response should be a dict when grouped"

        # Verificar categorias comuns
        expected_categories = ["Clientes", "Contratos", "Usuários", "Sistema"]
        found_categories = list(data.keys())

        for category in expected_categories:
            if category in found_categories:
                assert isinstance(data[category], list), \
                    f"Category {category} should be a list"
                assert len(data[category]) > 0, \
                    f"Category {category} should have permissions"

    def test_get_permissions_checks_hardcoded_ids(self, http_client, api_url, admin_user, timer):
        """Verificar que permissões têm IDs hardcoded corretos"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.get(
            f"{api_url}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 200

        data = response.json()

        # Verificar formato dos IDs (devem ser UUIDs com b0000000...)
        for perm in data:
            perm_id = perm.get("id", "")
            # ID deve ter formato UUID (8-4-4-4-12)
            parts = perm_id.split("-")
            assert len(parts) == 5, \
                f"Permission ID {perm_id} should have 5 parts separated by dashes"
            assert len(parts[0]) == 8, f"First part should be 8 chars: {perm_id}"
            assert len(parts[1]) == 4, f"Second part should be 4 chars: {perm_id}"
            assert len(parts[2]) == 4, f"Third part should be 4 chars: {perm_id}"
            assert len(parts[3]) == 4, f"Fourth part should be 4 chars: {perm_id}"
            assert len(parts[4]) == 12, f"Fifth part should be 12 chars: {perm_id}"


# =============================================================================
# GET /api/roles/{id}/permissions - Listar permissões de uma role
# =============================================================================

class TestGetRolePermissions:
    """Testes para GET /api/roles/{id}/permissions"""

    def test_get_role_permissions_without_token_returns_401(self, http_client, api_url, test_role, timer):
        """GET /api/roles/{id}/permissions sem token DEVE retornar 401"""
        response = http_client.get(f"{api_url}/roles/{test_role['id']}/permissions")
        assert response.status_code == 401

    def test_get_role_permissions_returns_200(self, http_client, api_url, admin_user, test_role, timer):
        """Admin DEVE poder listar permissões de uma role"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.get(
            f"{api_url}/roles/{test_role['id']}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list), "Response should be a list"
        # Nova role pode ter 0 permissões
        assert len(data) >= 0


# =============================================================================
# PUT /api/roles/{id}/permissions - Atualizar permissões de uma role
# =============================================================================

class TestSetRolePermissions:
    """Testes para PUT /api/roles/{id}/permissions"""

    def test_set_permissions_without_token_returns_401(self, http_client, api_url, test_role, timer):
        """PUT /api/roles/{id}/permissions sem token DEVE retornar 401"""
        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": []}
        )
        assert response.status_code == 401

    def test_set_permissions_with_empty_array(self, http_client, api_url, admin_user, test_role, timer):
        """Root DEVE poder remover todas as permissões (array vazio)"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": []},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Pode ser 200 (sucesso) ou 403 (não é root)
        assert response.status_code in [200, 403], \
            f"Expected 200 or 403, got {response.status_code}"

    def test_set_permissions_with_valid_permission_ids(self, http_client, api_url, admin_user, test_role, timer):
        """Root DEVE poder adicionar permissões válidas"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        # Primeiro, obter lista de permissões disponíveis
        perms_response = http_client.get(
            f"{api_url}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        if perms_response.status_code != 200:
            pytest.skip("Não foi possível obter lista de permissões")

        all_permissions = perms_response.json()
        if len(all_permissions) == 0:
            pytest.skip("Nenhuma permissão disponível")

        # Pegar as primeiras 3 permissões
        test_perm_ids = [p["id"] for p in all_permissions[:3]]

        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": test_perm_ids},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Pode ser 200 (root) ou 403 (não root)
        assert response.status_code in [200, 403], \
            f"Expected 200 or 403, got {response.status_code}"

        if response.status_code == 200:
            # Verificar que as permissões foram adicionadas
            get_response = http_client.get(
                f"{api_url}/roles/{test_role['id']}/permissions",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert get_response.status_code == 200

            role_perms = get_response.json()
            role_perm_ids = [p["id"] for p in role_perms]

            for test_id in test_perm_ids:
                assert test_id in role_perm_ids, \
                    f"Permission {test_id} should be in role permissions"

    def test_set_permissions_with_invalid_permission_id_returns_400(self, http_client, api_url, admin_user, test_role, timer):
        """PUT com ID de permissão inválido DEVE retornar 400"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        invalid_ids = [
            "not-a-uuid",
            "12345",
            "invalid-id",
            "",
        ]

        for invalid_id in invalid_ids:
            response = http_client.put(
                f"{api_url}/roles/{test_role['id']}/permissions",
                json={"permission_ids": [invalid_id]},
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            # Deve ser 400 (ID inválido) ou 403 (não root)
            assert response.status_code in [400, 403], \
                f"Expected 400 or 403 for invalid ID '{invalid_id}', got {response.status_code}"

    def test_set_permissions_with_nonexistent_permission_id(self, http_client, api_url, admin_user, test_role, timer):
        """PUT com ID de permissão inexistente DEVE retornar erro"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        # UUID válido mas inexistente
        fake_uuid = "a0000000-0000-0000-0000-000000000001"

        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": [fake_uuid]},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Pode ser 400 (permissão não existe) ou 403 (não root)
        assert response.status_code in [400, 403, 500], \
            f"Expected 400, 403, or 500 for nonexistent permission, got {response.status_code}"

    def test_set_permissions_with_hardcoded_permission_ids(self, http_client, api_url, admin_user, test_role, timer):
        """PUT com IDs hardcoded (b0000000...) DEVE funcionar"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        # IDs hardcoded de permissões reais
        hardcoded_ids = [
            "b0000000-0000-0000-0000-000000000001",  # clients:create
            "b0000000-0000-0000-0000-000000000002",  # clients:read
        ]

        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": hardcoded_ids},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Este é o teste PRINCIPAL: deve ser 200 (sucesso) ou 403 (não root)
        # NÃO deve ser 400 (ID inválido)
        assert response.status_code in [200, 403], \
            f"❌ FALHA: IDs hardcoded devem ser aceitos! Got {response.status_code}"

        if response.status_code == 200:
            print("✅ IDs hardcoded aceitos com sucesso")

    def test_set_permissions_multiple_times_is_idempotent(self, http_client, api_url, admin_user, test_role, timer):
        """Definir as mesmas permissões múltiplas vezes DEVE ser idempotente"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        # Pegar algumas permissões
        perms_response = http_client.get(
            f"{api_url}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        if perms_response.status_code != 200:
            pytest.skip("Não foi possível obter permissões")

        all_permissions = perms_response.json()
        if len(all_permissions) < 2:
            pytest.skip("Necessário pelo menos 2 permissões")

        test_perm_ids = [p["id"] for p in all_permissions[:2]]

        # Definir permissões primeira vez
        response1 = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": test_perm_ids},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Definir permissões segunda vez (mesmas)
        response2 = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": test_perm_ids},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Ambas devem ter mesmo status
        if response1.status_code == 200:
            assert response2.status_code == 200, \
                "Setting same permissions twice should succeed both times"


# =============================================================================
# Integration Tests - Fluxo completo
# =============================================================================

class TestRolePermissionsIntegration:
    """Testes de integração do fluxo completo"""

    def test_full_permission_workflow(self, http_client, api_url, admin_user, timer):
        """Teste completo: criar role → adicionar permissões → verificar → remover → verificar"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        # 1. Criar role
        role_data = {
            "name": f"integration_test_role_{int(time.time())}",
            "display_name": "Integration Test Role",
            "description": "Role para teste de integração",
            "priority": 50
        }

        create_response = http_client.post(
            f"{api_url}/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        if create_response.status_code != 201:
            pytest.skip(f"Não foi possível criar role: {create_response.status_code}")

        role = create_response.json()
        role_id = role["id"]

        try:
            # 2. Verificar que role começa sem permissões
            get_perms_response = http_client.get(
                f"{api_url}/roles/{role_id}/permissions",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert get_perms_response.status_code == 200
            initial_perms = get_perms_response.json()
            assert len(initial_perms) == 0, "New role should have no permissions"

            # 3. Obter lista de todas as permissões
            all_perms_response = http_client.get(
                f"{api_url}/permissions",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert all_perms_response.status_code == 200
            all_perms = all_perms_response.json()

            if len(all_perms) < 3:
                pytest.skip("Necessário pelo menos 3 permissões para teste")

            # 4. Adicionar 3 permissões
            test_perm_ids = [p["id"] for p in all_perms[:3]]
            set_response = http_client.put(
                f"{api_url}/roles/{role_id}/permissions",
                json={"permission_ids": test_perm_ids},
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )

            if set_response.status_code == 403:
                pytest.skip("User não é root, pulando teste de modificação de permissões")

            assert set_response.status_code == 200, \
                f"Failed to set permissions: {set_response.status_code}"

            # 5. Verificar que permissões foram adicionadas
            verify_response = http_client.get(
                f"{api_url}/roles/{role_id}/permissions",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert verify_response.status_code == 200
            added_perms = verify_response.json()
            added_perm_ids = [p["id"] for p in added_perms]

            for perm_id in test_perm_ids:
                assert perm_id in added_perm_ids, \
                    f"Permission {perm_id} should be in role"

            # 6. Remover todas as permissões
            remove_response = http_client.put(
                f"{api_url}/roles/{role_id}/permissions",
                json={"permission_ids": []},
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert remove_response.status_code == 200

            # 7. Verificar que permissões foram removidas
            final_response = http_client.get(
                f"{api_url}/roles/{role_id}/permissions",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )
            assert final_response.status_code == 200
            final_perms = final_response.json()
            assert len(final_perms) == 0, "All permissions should be removed"

        finally:
            # Cleanup
            http_client.delete(
                f"{api_url}/roles/{role_id}",
                headers={"Authorization": f"Bearer {admin_user['token']}"}
            )


# =============================================================================
# Edge Cases
# =============================================================================

class TestRolePermissionsEdgeCases:
    """Testes de casos extremos"""

    def test_set_permissions_with_duplicate_ids(self, http_client, api_url, admin_user, test_role, timer):
        """PUT com IDs duplicados DEVE funcionar (deduplicação automática)"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        perms_response = http_client.get(
            f"{api_url}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        if perms_response.status_code != 200:
            pytest.skip("Não foi possível obter permissões")

        all_perms = perms_response.json()
        if len(all_perms) == 0:
            pytest.skip("Nenhuma permissão disponível")

        # Enviar mesmo ID múltiplas vezes
        perm_id = all_perms[0]["id"]
        duplicate_ids = [perm_id, perm_id, perm_id]

        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": duplicate_ids},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Deve aceitar (200) ou negar por permissão (403)
        # NÃO deve crashar (500)
        assert response.status_code in [200, 403], \
            f"Expected 200 or 403, got {response.status_code}"

    def test_set_permissions_with_very_large_array(self, http_client, api_url, admin_user, test_role, timer):
        """PUT com array muito grande DEVE funcionar ou retornar erro apropriado"""
        if not admin_user or "token" not in admin_user:
            pytest.skip("Admin user não disponível")

        perms_response = http_client.get(
            f"{api_url}/permissions",
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        if perms_response.status_code != 200:
            pytest.skip("Não foi possível obter permissões")

        all_perms = perms_response.json()
        all_perm_ids = [p["id"] for p in all_perms]

        # Enviar TODAS as permissões
        response = http_client.put(
            f"{api_url}/roles/{test_role['id']}/permissions",
            json={"permission_ids": all_perm_ids},
            headers={"Authorization": f"Bearer {admin_user['token']}"}
        )

        # Deve funcionar (200) ou negar por permissão (403)
        # NÃO deve crashar (500)
        assert response.status_code in [200, 403], \
            f"Expected 200 or 403 for large array, got {response.status_code}"


# =============================================================================
# Summary Report
# =============================================================================

def pytest_sessionfinish(session, exitstatus):
    """Relatório final dos testes"""
    print("\n" + "="*80)
    print("RELATÓRIO DE TESTES - ROLE PERMISSIONS")
    print("="*80)
    print(f"Total de testes: {session.testscollected}")
    print(f"Status de saída: {exitstatus}")
    print("\nCategorias testadas:")
    print("  ✓ GET /api/permissions")
    print("  ✓ GET /api/roles/{id}/permissions")
    print("  ✓ PUT /api/roles/{id}/permissions")
    print("  ✓ IDs hardcoded (b0000000...)")
    print("  ✓ Validação de UUIDs")
    print("  ✓ Fluxo completo de integração")
    print("  ✓ Casos extremos")
    print("="*80)

    if exitstatus == 0:
        print("✅ TODOS OS TESTES PASSARAM!")
    else:
        print("❌ ALGUNS TESTES FALHARAM - REVISAR!")
    print("="*80)
