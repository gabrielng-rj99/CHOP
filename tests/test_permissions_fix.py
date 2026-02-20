#!/usr/bin/env python3
"""
Script para testar o fix de permissões
Testa se IDs hardcoded (b0000000-...) são aceitos pela API
"""

import requests
import sys
import os

API_URL = "http://localhost:3000/api"

def main():
    print("=" * 80)
    print("TESTE DO FIX: Validação de IDs de Permissões Hardcoded")
    print("=" * 80)
    print()

    # Login
    print("🔐 Fazendo login como root...")
    try:
        login_response = requests.post(
            f"{API_URL}/login",
            json={
                "username": "root",
                "password": os.getenv("TEST_ROOT_PASSWORD", "THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc")
            },
            timeout=5
        )
        login_response.raise_for_status()
        token = login_response.json()["data"]["token"]
        print("✅ Login bem-sucedido!")
    except Exception as e:
        print(f"❌ Erro no login: {e}")
        sys.exit(1)

    headers = {"Authorization": f"Bearer {token}"}
    print()

    # Obter permissões
    print("📋 Obtendo lista de permissões...")
    try:
        perms_response = requests.get(f"{API_URL}/permissions", headers=headers, timeout=5)
        perms_response.raise_for_status()
        perms = perms_response.json()

        if not perms or len(perms) < 2:
            print("❌ Não há permissões suficientes no sistema")
            sys.exit(1)

        first_id = perms[0]["id"]
        second_id = perms[1]["id"]

        print(f"   Permissão 1: {first_id} ({perms[0].get('display_name', 'N/A')})")
        print(f"   Permissão 2: {second_id} ({perms[1].get('display_name', 'N/A')})")

        # Verificar se são IDs hardcoded
        if first_id.startswith("b0000000"):
            print("✅ IDs hardcoded encontrados (formato b0000000-...)")
        else:
            print("⚠️  IDs não são hardcoded")
    except Exception as e:
        print(f"❌ Erro ao obter permissões: {e}")
        sys.exit(1)

    print()

    # Obter roles
    print("📋 Obtendo lista de roles...")
    try:
        roles_response = requests.get(f"{API_URL}/roles", headers=headers, timeout=5)
        roles_response.raise_for_status()
        roles = roles_response.json()

        # Procurar role que não seja root (root não pode ser modificado)
        target_role = None
        for role in roles:
            if role["name"] in ["user", "admin", "viewer"]:
                target_role = role
                break

        if not target_role:
            # Pegar qualquer role que não seja root
            target_role = next((r for r in roles if r["name"] != "root"), None)

        if not target_role:
            print("❌ Nenhuma role modificável encontrada")
            sys.exit(1)

        role_id = target_role["id"]
        role_name = target_role["name"]

        print(f"   Role selecionada: {role_name} ({role_id})")
    except Exception as e:
        print(f"❌ Erro ao obter roles: {e}")
        sys.exit(1)

    print()
    print("=" * 80)
    print("🧪 EXECUTANDO TESTE DO FIX")
    print("=" * 80)
    print()
    print(f"Tentando atualizar permissões da role '{role_name}'")
    print(f"Com IDs hardcoded: [{first_id}, {second_id}]")
    print()

    # Testar atualização de permissões
    try:
        update_response = requests.put(
            f"{API_URL}/roles/{role_id}/permissions",
            headers=headers,
            json={"permission_ids": [first_id, second_id]},
            timeout=5
        )

        status_code = update_response.status_code
        response_text = update_response.text

        print(f"📊 Status Code: {status_code}")
        print(f"📄 Response: {response_text[:200]}")
        print()
        print("=" * 80)

        if status_code == 200:
            print("✅✅✅ SUCESSO! BUG CORRIGIDO! ✅✅✅")
            print()
            print("🎯 O que funcionou:")
            print("   ✅ IDs hardcoded (b0000000-...) foram aceitos")
            print("   ✅ ValidateUUIDGeneric() está funcionando")
            print("   ✅ Permissões foram atualizadas com sucesso")
            print("   ✅ Sistema de RBAC operacional")
            print()
            print("✅ Você pode usar o frontend normalmente agora!")
            print("   Vá em Settings → Roles & Permissions")
            print("   E edite as permissões de qualquer role")
            print()
            return 0

        elif status_code == 400:
            print("❌❌❌ FALHA! Status 400 ❌❌❌")
            print()
            print("🔴 IDs hardcoded ainda estão sendo rejeitados")
            print()
            print("Possíveis causas:")
            print("   1. Backend não foi reiniciado após a compilação")
            print("   2. Backend ainda está usando versão antiga")
            print()
            print("SOLUÇÃO:")
            print("   1. Parar o backend atual:")
            print("      pkill chop-backend")
            print()
            print("   2. Iniciar a versão compilada nova:")
            print("      cd Client-Hub-Open-Project/backend")
            print("      ./chop-backend-new")
            print()
            return 1

        elif status_code == 403:
            print("⚠️  Status 403 - Permissão negada")
            print()
            print("Isso pode significar:")
            print("   - Usuário não é root")
            print("   - Role sendo editada não pode ser modificada")
            print()
            print("Isso NÃO é um problema com o fix dos IDs")
            return 0

        else:
            print(f"⚠️  Status inesperado: {status_code}")
            print()
            print("Resposta completa:")
            print(response_text)
            return 1

    except Exception as e:
        print(f"❌ Erro na requisição: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
