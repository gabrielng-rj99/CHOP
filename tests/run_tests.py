#!/usr/bin/env python3
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
MASTER TEST RUNNER - Client Hub Open Project
Executa todos os testes com cronometragem detalhada e gera relatórios

Portas do ambiente de teste:
- Database: 65432
- Backend: 63000
- Frontend: 65080
"""

import subprocess
import sys
import time
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Cores para terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configurações de ambiente de teste
TEST_CONFIG = {
    "DB_HOST": os.getenv("DB_HOST", "localhost"),
    "DB_PORT": os.getenv("TEST_DB_PORT", "65432"),
    "BACKEND_PORT": os.getenv("TEST_BACKEND_PORT", "63000"),
    "FRONTEND_PORT": os.getenv("TEST_FRONTEND_PORT", "65080"),
    "API_URL": os.getenv("TEST_API_URL", "http://localhost:63000/api"),
}

def print_header(text: str):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(70)}{Colors.END}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.END}\n")

def print_section(text: str):
    print(f"\n{Colors.CYAN}{Colors.BOLD}▶ {text}{Colors.END}\n")

def print_subsection(text: str):
    print(f"  {Colors.BLUE}► {text}{Colors.END}")

def print_success(text: str):
    print(f"  {Colors.GREEN}✓{Colors.END} {text}")

def print_error(text: str):
    print(f"  {Colors.RED}✗{Colors.END} {text}")

def print_warning(text: str):
    print(f"  {Colors.YELLOW}⚠{Colors.END} {text}")

def print_info(text: str):
    print(f"  {Colors.BLUE}ℹ{Colors.END} {text}")

def print_timing(label: str, duration: float):
    print(f"  {Colors.CYAN}⏱️{Colors.END}  {label}: {format_duration(duration)}")

def format_duration(seconds: float) -> str:
    """Formata duração em formato legível"""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {mins}m {secs:.0f}s"

def check_dependencies() -> bool:
    """Verifica se dependências estão instaladas"""
    print_section("Verificando Dependências")

    dependencies_ok = True

    # Python
    print_info(f"Python: {sys.version.split()[0]}")

    # pytest
    try:
        result = subprocess.run(["pytest", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip().split()[1] if result.stdout.strip() else "unknown"
            print_success(f"pytest: {version}")
        else:
            print_error("pytest não encontrado")
            dependencies_ok = False
    except FileNotFoundError:
        print_error("pytest não encontrado")
        print_info("Execute: pip install -r requirements.txt")
        dependencies_ok = False

    # requests
    try:
        import requests
        print_success(f"requests: {requests.__version__}")
    except ImportError:
        print_error("requests não instalado")
        dependencies_ok = False

    # PyJWT
    try:
        import jwt
        print_success(f"PyJWT: {jwt.__version__}")
    except ImportError:
        print_warning("PyJWT não instalado (alguns testes podem falhar)")

    return dependencies_ok

def check_backend_running() -> bool:
    """Verifica se backend está rodando na porta de teste"""
    print_section("Verificando Backend")

    backend_url = f"http://localhost:{TEST_CONFIG['BACKEND_PORT']}"

    try:
        import requests
        response = requests.get(f"{backend_url}/health", timeout=5)
        if response.status_code == 200:
            print_success(f"Backend está online ({backend_url})")
            data = response.json()
            print_info(f"Status: {data.get('status', 'unknown')}")
            return True
        else:
            print_error(f"Backend respondeu com status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print_error("Backend não está rodando")
        print_info(f"Inicie o ambiente de teste:")
        print_info(f"  cd tests && docker-compose -f docker-compose.test.yml up -d")
        return False
    except Exception as e:
        print_error(f"Erro ao conectar: {str(e)}")
        return False

def check_database_running() -> bool:
    """Verifica se o banco de teste está rodando"""
    print_section("Verificando Banco de Dados")

    db_port = TEST_CONFIG['DB_PORT']

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', int(db_port)))
        sock.close()

        if result == 0:
            print_success(f"PostgreSQL está rodando na porta {db_port}")
            return True
        else:
            print_error(f"PostgreSQL não está acessível na porta {db_port}")
            return False
    except Exception as e:
        print_error(f"Erro ao verificar banco: {str(e)}")
        return False

def run_go_tests() -> Tuple[bool, float, Dict]:
    """Executa testes unitários em Go"""
    print_section("Executando Testes Unitários (Go)")

    start = time.time()

    try:
        backend_path = Path(__file__).parent.parent / "backend"

        if not backend_path.exists():
            print_warning(f"Diretório backend não encontrado: {backend_path}")
            return False, 0, {}

        env["POSTGRES_HOST"] = TEST_CONFIG["DB_HOST"]
        env["POSTGRES_PORT"] = TEST_CONFIG["DB_PORT"]
        env["POSTGRES_USER"] = "test_user"
        env["POSTGRES_PASSWORD"] = "test_password"
        env["POSTGRES_DB"] = "contracts_test"
        
        result = subprocess.run(
            ["go", "test", "-v", "-cover", "-coverprofile=coverage.out", "./..."],
            cwd=backend_path,
            capture_output=True,
            text=True,
            timeout=180,
            env=env
        )

        duration = time.time() - start

        # Parse output
        output = result.stdout + result.stderr
        lines = output.split('\n')

        passed = len([l for l in lines if '--- PASS:' in l])
        failed = len([l for l in lines if '--- FAIL:' in l])
        skipped = len([l for l in lines if '--- SKIP:' in l])

        # Extrair coverage
        coverage = 0.0
        for line in lines:
            if 'coverage:' in line:
                try:
                    cov_str = line.split('coverage:')[1].split('%')[0].strip()
                    coverage = float(cov_str)
                except:
                    pass

        stats = {
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
            'coverage': coverage,
            'duration': duration
        }

        print_info(f"Passou: {passed} | Falhou: {failed} | Pulado: {skipped}")
        if coverage > 0:
            print_info(f"Coverage: {coverage:.1f}%")
        print_timing("Duração", duration)

        return result.returncode == 0, duration, stats

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        print_error(f"Timeout após {format_duration(duration)}")
        return False, duration, {'error': 'timeout'}
    except FileNotFoundError:
        print_warning("Go não instalado - pulando testes unitários")
        return True, 0, {'skipped': True}
    except Exception as e:
        duration = time.time() - start
        print_error(f"Erro: {str(e)}")
        return False, duration, {'error': str(e)}

def run_pytest(markers: str = None, verbose: bool = True, html_report: str = None) -> Tuple[bool, float, Dict]:
    """Executa testes Python com pytest"""
    start = time.time()

    cmd = ["pytest"]

    if verbose:
        cmd.append("-v")

    cmd.extend(["--tb=short", "--color=yes"])

    if markers:
        cmd.extend(["-m", markers])

    if html_report:
        cmd.extend(["--html", html_report, "--self-contained-html"])

    # Adicionar timeout
    cmd.extend(["--timeout=60"])

    try:
        result = subprocess.run(
            cmd,
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
            timeout=600
        )

        duration = time.time() - start

        # Parse output pytest
        output = result.stdout + result.stderr
        lines = output.split('\n')

        passed = failed = skipped = errors = 0

        # Procurar linha de resumo
        for line in lines:
            if 'passed' in line or 'failed' in line or 'error' in line:
                # Formato: "X passed, Y failed, Z skipped, W error in Ns"
                parts = line.split(',')
                for part in parts:
                    part = part.strip()
                    if 'passed' in part:
                        try:
                            passed = int(part.split()[0])
                        except:
                            pass
                    elif 'failed' in part:
                        try:
                            failed = int(part.split()[0])
                        except:
                            pass
                    elif 'skipped' in part:
                        try:
                            skipped = int(part.split()[0])
                        except:
                            pass
                    elif 'error' in part:
                        try:
                            errors = int(part.split()[0])
                        except:
                            pass

        stats = {
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
            'errors': errors,
            'duration': duration
        }

        # Mostrar output se houve falhas
        if result.returncode != 0:
            print(output)

        return result.returncode == 0, duration, stats

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        print_error(f"Timeout após {format_duration(duration)}")
        return False, duration, {'error': 'timeout'}
    except Exception as e:
        duration = time.time() - start
        print_error(f"Erro: {str(e)}")
        return False, duration, {'error': str(e)}

def run_test_category(name: str, marker: str, results: Dict) -> None:
    """Executa uma categoria de testes"""
    print_section(f"Executando {name}")

    success, duration, stats = run_pytest(markers=marker)
    results[name] = {
        'success': success,
        'duration': duration,
        'stats': stats
    }

    passed = stats.get('passed', 0)
    failed = stats.get('failed', 0)
    skipped = stats.get('skipped', 0)

    if success:
        print_success(f"{name} concluídos: {passed} passou, {failed} falhou, {skipped} pulado")
    else:
        print_error(f"{name} com falhas: {passed} passou, {failed} falhou, {skipped} pulado")

    print_timing("Duração", duration)

def generate_report(results: Dict, total_duration: float) -> int:
    """Gera relatório final"""
    print_header("RELATÓRIO FINAL")

    # Calcular totais
    total_passed = sum(r.get('stats', {}).get('passed', 0) for r in results.values())
    total_failed = sum(r.get('stats', {}).get('failed', 0) for r in results.values())
    total_skipped = sum(r.get('stats', {}).get('skipped', 0) for r in results.values())
    total_errors = sum(r.get('stats', {}).get('errors', 0) for r in results.values())
    total_tests = total_passed + total_failed + total_skipped + total_errors

    # Tabela de resumo
    print(f"\n{'Categoria':<35} {'Passou':<10} {'Falhou':<10} {'Pulado':<10} {'Tempo':<12}")
    print("=" * 80)

    for name, data in results.items():
        stats = data.get('stats', {})
        duration = data.get('duration', 0)

        passed = stats.get('passed', 0)
        failed = stats.get('failed', 0)
        skipped = stats.get('skipped', 0)

        status_color = Colors.GREEN if data.get('success') else Colors.RED
        passed_str = f"{Colors.GREEN}{passed}{Colors.END}"
        failed_str = f"{Colors.RED}{failed}{Colors.END}" if failed > 0 else str(failed)
        skipped_str = f"{Colors.YELLOW}{skipped}{Colors.END}" if skipped > 0 else str(skipped)

        print(f"{name:<35} {passed_str:<19} {failed_str:<19} {skipped_str:<19} {format_duration(duration):<12}")

    print("=" * 80)

    # Totais
    total_passed_str = f"{Colors.GREEN}{total_passed}{Colors.END}"
    total_failed_str = f"{Colors.RED}{total_failed}{Colors.END}" if total_failed > 0 else str(total_failed)
    total_skipped_str = f"{Colors.YELLOW}{total_skipped}{Colors.END}" if total_skipped > 0 else str(total_skipped)

    print(f"{'TOTAL':<35} {total_passed_str:<19} {total_failed_str:<19} {total_skipped_str:<19} {format_duration(total_duration):<12}")

    # Taxa de sucesso
    if total_tests > 0:
        success_rate = (total_passed / total_tests) * 100
        rate_color = Colors.GREEN if success_rate >= 90 else (Colors.YELLOW if success_rate >= 70 else Colors.RED)
        print(f"\n{Colors.BOLD}Taxa de Sucesso: {rate_color}{success_rate:.1f}%{Colors.END}")

    # Cobertura Go
    go_stats = results.get('Testes Unitários Go', {}).get('stats', {})
    if 'coverage' in go_stats and go_stats['coverage'] > 0:
        coverage = go_stats['coverage']
        cov_color = Colors.GREEN if coverage >= 80 else (Colors.YELLOW if coverage >= 60 else Colors.RED)
        print(f"{Colors.BOLD}Coverage Go: {cov_color}{coverage:.1f}%{Colors.END}")

    # Status final
    print()
    all_success = all(r.get('success', False) for r in results.values())

    if all_success and total_failed == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}✅ TODOS OS TESTES PASSARAM! 🎉{Colors.END}")
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}❌ ALGUNS TESTES FALHARAM{Colors.END}")
        return 1

def save_json_report(results: Dict, total_duration: float, filepath: str):
    """Salva relatório em JSON"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_duration": total_duration,
        "environment": TEST_CONFIG,
        "results": results,
        "summary": {
            "total_passed": sum(r.get('stats', {}).get('passed', 0) for r in results.values()),
            "total_failed": sum(r.get('stats', {}).get('failed', 0) for r in results.values()),
            "total_skipped": sum(r.get('stats', {}).get('skipped', 0) for r in results.values()),
        }
    }

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2)

    print_info(f"Relatório JSON salvo em: {filepath}")

def main():
    """Função principal"""
    print_header("SUITE DE TESTES - Client Hub")

    print(f"  📅 Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  🔧 Ambiente de Teste:")
    print(f"     - Database Port: {TEST_CONFIG['DB_PORT']}")
    print(f"     - Backend Port: {TEST_CONFIG['BACKEND_PORT']}")
    print(f"     - Frontend Port: {TEST_CONFIG['FRONTEND_PORT']}")
    print(f"     - API URL: {TEST_CONFIG['API_URL']}")

    start_total = time.time()
    results = {}

    # 1. Verificar dependências
    if not check_dependencies():
        print_error("Dependências faltando. Abortando.")
        return 1

    # 2. Verificar banco de dados
    db_running = check_database_running()

    # 3. Verificar backend
    backend_running = check_backend_running()

    if not backend_running:
        print_warning("Backend não está rodando. Alguns testes podem falhar.")
        response = input("\nContinuar mesmo assim? (s/N): ")
        if response.lower() != 's':
            return 1

    # 4. Testes unitários Go
    print_section("Testes Unitários Go")
    success, duration, stats = run_go_tests()
    results['Testes Unitários Go'] = {
        'success': success,
        'duration': duration,
        'stats': stats
    }

    # 5. Testes de segurança JWT
    run_test_category("Testes JWT", "jwt", results)

    # 6. Testes SQL Injection
    run_test_category("Testes SQL Injection", "sql_injection", results)

    # 7. Testes de XSS
    run_test_category("Testes XSS", "xss", results)

    # 8. Testes de Autorização
    run_test_category("Testes Autorização", "authorization", results)

    # 9. Testes de Validação de Senha
    run_test_category("Testes Senha", "password", results)

    # 10. Testes de Validação de Entrada
    run_test_category("Testes Validação", "validation", results)

    # 11. Testes de Bloqueio de Login
    run_test_category("Testes Login Blocking", "login_blocking", results)

    # 12. Testes de Vazamento de Dados
    run_test_category("Testes Data Leakage", "data_leakage", results)

    # 13. Testes de API
    run_test_category("Testes API", "api", results)

    # 14. Testes de Inicialização
    run_test_category("Testes Inicialização", "initialization", results)

    # 15. Testes de CORS
    run_test_category("Testes CORS", "cors", results)

    # 16. Testes de Headers HTTP
    run_test_category("Testes Headers", "headers", results)

    # 17. Testes de Concorrência
    run_test_category("Testes Concorrência", "concurrency", results)

    # 18. Testes de Rate Limiting
    run_test_category("Testes Rate Limiting", "rate_limiting", results)

    # 14. Todos os testes Python (completo com relatório HTML)
    print_section("Executando Todos os Testes Python (Relatório Completo)")

    reports_dir = Path(__file__).parent / "test_reports"
    reports_dir.mkdir(exist_ok=True)

    html_report_path = reports_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    success, duration, stats = run_pytest(html_report=str(html_report_path))
    results['Todos os Testes'] = {
        'success': success,
        'duration': duration,
        'stats': stats
    }

    if html_report_path.exists():
        print_success(f"Relatório HTML: {html_report_path}")

    # Duração total
    total_duration = time.time() - start_total

    # Salvar relatório JSON
    json_report_path = reports_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_json_report(results, total_duration, str(json_report_path))

    # Gerar relatório final
    exit_code = generate_report(results, total_duration)

    print(f"\n{Colors.BOLD}Duração Total: {format_duration(total_duration)}{Colors.END}")
    print(f"{Colors.BOLD}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    print(f"\n{Colors.CYAN}Relatórios salvos em: {reports_dir}{Colors.END}\n")

    return exit_code

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Testes interrompidos pelo usuário{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}Erro fatal: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
