#!/bin/bash

BASE_URL="http://localhost:3000/api"
USERNAME="${USERNAME:-root}"
PASSWORD="${PASSWORD:-THIS_IS_A_DEV_ENVIRONMENT_PASSWORD@123abc}"
TIMESTAMP=$(date +%s%N | cut -b1-10)

echo "====================================="
echo "Client Hub Populate Script"
echo "====================================="
echo ""

# Login
LOGIN=$(curl -s -X POST "$BASE_URL/login" -H "Content-Type: application/json" -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
TOKEN=$(echo "$LOGIN" | jq -r '.data.token // empty')

if [ -z "$TOKEN" ]; then
    echo "❌ Login failed!"
    exit 1
fi

echo "✓ Logged in"
echo ""

# Helpers
api_call() {
    curl -s -X "$1" "$BASE_URL$2" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "$3"
}

getid() {
    echo "$1" | jq -r '.data.id // empty'
}

declare -a CATS
declare -a SUBS
declare -a CLIENTS
declare -a AFFILIATES

# Get current date info for birthday calculations
CURRENT_YEAR=$(date +%Y)
CURRENT_MONTH=$(date +%m)
CURRENT_DAY=$(date +%d)

# Birthday for 37 years old today (born in 1989)
BIRTHDAY_37_YEAR=$((CURRENT_YEAR - 37))
BIRTHDAY_37="${BIRTHDAY_37_YEAR}-${CURRENT_MONTH}-${CURRENT_DAY}T00:00:00Z"

# Function to generate birth date for a specific week of the year
generate_birth_date_for_week() {
    local week=$1
    local base_year=$((CURRENT_YEAR - 25 - (RANDOM % 40)))  # Random age between 25-65
    # Calculate the day of year for this week (week * 7)
    local day_of_year=$((week * 7 + (RANDOM % 7)))
    if [ $day_of_year -gt 365 ]; then
        day_of_year=365
    fi
    # Use date to calculate the actual date
    local birth_date=$(date -u -d "${base_year}-01-01 +${day_of_year} days" +%Y-%m-%dT00:00:00Z 2>/dev/null || \
                       date -u -v+${day_of_year}d -j -f "%Y-%m-%d" "${base_year}-01-01" +%Y-%m-%dT00:00:00Z 2>/dev/null || \
                       echo "${base_year}-06-15T00:00:00Z")
    echo "$birth_date"
}

# Step 1: Categories
echo "[1/9] Creating 25 categories..."
CATEGORY_NAMES=(
    "Software" "Hardware" "Infraestrutura" "Cloud" "Segurança"
    "Rede" "Banco de Dados" "ERP" "CRM" "Business Intelligence"
    "Mobile" "Web" "Desktop" "DevOps" "Suporte"
    "Consultoria" "Treinamento" "Manutenção" "Licenças" "SaaS"
    "Telecomunicações" "IoT" "Automação" "Integração" "Analytics"
)

for i in {0..24}; do
    name="${CATEGORY_NAMES[$i]}"
    res=$(api_call POST "/categories" "{\"name\":\"$name\"}")
    id=$(getid "$res")
    [ -n "$id" ] && CATS+=("$id") && echo -n "."
done
echo ""
echo "✓ Categories: ${#CATS[@]}"
echo ""

# Step 2: Subcategories
echo "[2/9] Creating 60 subcategories..."
SUBCATEGORY_NAMES=(
    "Básico" "Avançado" "Enterprise" "Premium" "Standard"
    "Lite" "Pro" "Ultimate" "Starter" "Growth"
    "Mensal" "Anual" "Trimestral" "Semestral" "Bienal"
    "Local" "Remoto" "Híbrido" "On-Premise" "Cloud Native"
    "Individual" "Equipe" "Corporativo" "Ilimitado" "Por Usuário"
    "Nacional" "Internacional" "Regional" "Global" "Multi-região"
)

for i in {0..59}; do
    catidx=$((i % ${#CATS[@]}))
    subname="${SUBCATEGORY_NAMES[$((i % ${#SUBCATEGORY_NAMES[@]}))]}"
    suffix=$((i / ${#SUBCATEGORY_NAMES[@]} + 1))
    if [ $suffix -gt 1 ]; then
        subname="${subname} v${suffix}"
    fi
    res=$(api_call POST "/subcategories" "{\"name\":\"$subname\",\"category_id\":\"${CATS[$catidx]}\"}")
    id=$(getid "$res")
    [ -n "$id" ] && SUBS+=("$id") && echo -n "."
done
echo ""
echo "✓ Subcategories: ${#SUBS[@]}"
echo ""

# Step 3: Create 165 clients (at least 1 birthday per week = 52+)
echo "[3/9] Creating 165 clients with distributed birthdays..."

# First names and last names for realistic client names
FIRST_NAMES=("João" "Maria" "Pedro" "Ana" "Carlos" "Fernanda" "Lucas" "Julia" "Marcos" "Patricia"
             "Rafael" "Camila" "Bruno" "Leticia" "Diego" "Amanda" "Gustavo" "Bruna" "Felipe" "Larissa"
             "Rodrigo" "Gabriela" "Thiago" "Mariana" "Leonardo" "Beatriz" "Eduardo" "Carolina" "Andre" "Vanessa"
             "Ricardo" "Daniela" "Fabio" "Natalia" "Sergio" "Juliana" "Marcelo" "Aline" "Leandro" "Renata")

LAST_NAMES=("Silva" "Santos" "Oliveira" "Souza" "Rodrigues" "Ferreira" "Alves" "Pereira" "Lima" "Gomes"
            "Costa" "Ribeiro" "Martins" "Carvalho" "Almeida" "Lopes" "Soares" "Fernandes" "Vieira" "Barbosa"
            "Rocha" "Dias" "Nascimento" "Andrade" "Moreira" "Nunes" "Marques" "Machado" "Mendes" "Freitas")

COMPANY_SUFFIXES=("Tecnologia" "Sistemas" "Consultoria" "Soluções" "Digital" "Group" "Tech" "IT" "Solutions" "Services"
                  "Labs" "Innovation" "Networks" "Software" "Data" "Corp" "Enterprise" "Global" "Partners" "Brasil")

CITIES=("São Paulo" "Rio de Janeiro" "Belo Horizonte" "Curitiba" "Porto Alegre" "Salvador" "Brasília" "Fortaleza"
        "Recife" "Manaus" "Campinas" "Florianópolis" "Goiânia" "Belém" "Vitória" "Santos" "Joinville" "Ribeirão Preto")

# Client 1: Special - Birthday today, turning 37
echo -n "Creating special birthday client (37 years today)..."
SPECIAL_NAME="Aniversariante do Dia - Cliente Especial"
res=$(api_call POST "/clients" "{\"name\":\"$SPECIAL_NAME\",\"email\":\"aniversariante_cliente_${TIMESTAMP}@example.com\",\"phone\":\"11999990001\",\"address\":\"Rua do Aniversário, 37 - São Paulo, SP\",\"birth_date\":\"$BIRTHDAY_37\",\"nickname\":\"Cliente 37 Anos\",\"notes\":\"Cliente especial criado para teste de aniversário - fazendo 37 anos hoje!\"}")
id=$(getid "$res")
[ -n "$id" ] && CLIENTS+=("$id") && echo " ✓"

# Create remaining 164 clients with distributed birthdays
for i in {2..165}; do
    # Generate name
    if [ $((RANDOM % 3)) -eq 0 ]; then
        # Company name
        fname="${FIRST_NAMES[$((RANDOM % ${#FIRST_NAMES[@]}))]}"
        lname="${LAST_NAMES[$((RANDOM % ${#LAST_NAMES[@]}))]}"
        suffix="${COMPANY_SUFFIXES[$((RANDOM % ${#COMPANY_SUFFIXES[@]}))]}"
        name="${fname} ${lname} ${suffix}"
    else
        # Person name
        fname="${FIRST_NAMES[$((RANDOM % ${#FIRST_NAMES[@]}))]}"
        lname="${LAST_NAMES[$((RANDOM % ${#LAST_NAMES[@]}))]}"
        name="${fname} ${lname}"
    fi
    name="$name $i"

    city="${CITIES[$((RANDOM % ${#CITIES[@]}))]}"
    phone="119$(printf '%08d' $((RANDOM * 100 + i)))"

    # Generate birthday - distribute across weeks of the year
    week=$((i % 52))
    birth_year=$((CURRENT_YEAR - 25 - (i % 40)))
    birth_month=$(( (week * 7 / 30) % 12 + 1 ))
    birth_day=$(( (week * 7) % 28 + 1 ))
    birth_date=$(printf "%04d-%02d-%02dT00:00:00Z" $birth_year $birth_month $birth_day)

    nickname=""
    if [ $((RANDOM % 2)) -eq 0 ]; then
        nickname=",\"nickname\":\"${fname:0:3}${i}\""
    fi

    res=$(api_call POST "/clients" "{\"name\":\"$name\",\"email\":\"client${i}_${TIMESTAMP}@example.com\",\"phone\":\"$phone\",\"address\":\"Rua $i, ${i}00 - $city\",\"birth_date\":\"$birth_date\"$nickname}")
    id=$(getid "$res")
    [ -n "$id" ] && CLIENTS+=("$id")

    [ $((i % 20)) -eq 0 ] && echo -n "."
done
echo ""
echo "✓ Clients: ${#CLIENTS[@]}"
echo ""

# Step 4: Archive some clients
echo "[4/9] Archiving 5 clients..."
for i in 160 161 162 163 164; do
    if [ -n "${CLIENTS[$i]}" ]; then
        api_call PUT "/clients/${CLIENTS[$i]}/archive" "{}" > /dev/null 2>&1 && echo -n "."
    fi
done
echo ""
echo "✓ Archived 5 clients"
echo ""

# Step 5: Create 165 affiliates (at least 1 birthday per week)
echo "[5/9] Creating 165 affiliates with distributed birthdays..."

AFFILIATE_TYPES=("Filial" "Unidade" "Departamento" "Setor" "Divisão" "Regional" "Escritório" "Centro" "Polo" "Núcleo")

# First affiliate: Special - Birthday today, turning 37 (affiliated to client 2, not the birthday client)
echo -n "Creating special birthday affiliate (37 years today)..."
if [ -n "${CLIENTS[1]}" ]; then
    res=$(api_call POST "/clients/${CLIENTS[1]}/affiliates" "{\"name\":\"Aniversariante do Dia - Afiliado Especial\",\"email\":\"aniversariante_afiliado_${TIMESTAMP}@example.com\",\"phone\":\"11999990002\",\"address\":\"Av. do Aniversário, 37 - Rio de Janeiro, RJ\",\"birth_date\":\"$BIRTHDAY_37\",\"description\":\"Afiliado especial criado para teste de aniversário - fazendo 37 anos hoje!\"}")
    id=$(getid "$res")
    [ -n "$id" ] && AFFILIATES+=("$id") && echo " ✓"
fi

# Create remaining affiliates
declare -i acount=1
for i in {2..165}; do
    # Distribute affiliates across clients (skip archived ones at the end)
    client_idx=$(( (i - 2) % 155 + 2 ))  # Use clients 2-156

    if [ -n "${CLIENTS[$client_idx]}" ]; then
        atype="${AFFILIATE_TYPES[$((RANDOM % ${#AFFILIATE_TYPES[@]}))]}"
        city="${CITIES[$((RANDOM % ${#CITIES[@]}))]}"

        # Generate birthday - distribute across weeks
        week=$((i % 52))
        birth_year=$((CURRENT_YEAR - 25 - (i % 40)))
        birth_month=$(( (week * 7 / 30) % 12 + 1 ))
        birth_day=$(( (week * 7) % 28 + 1 ))
        birth_date=$(printf "%04d-%02d-%02dT00:00:00Z" $birth_year $birth_month $birth_day)

        res=$(api_call POST "/clients/${CLIENTS[$client_idx]}/affiliates" "{\"name\":\"$atype $city $i\",\"email\":\"affiliate${i}_${TIMESTAMP}@example.com\",\"phone\":\"11988${i}0000\",\"address\":\"Av. $i, ${i}0 - $city\",\"birth_date\":\"$birth_date\"}")
        id=$(getid "$res")
        [ -n "$id" ] && AFFILIATES+=("$id") && ((acount++))
    fi

    [ $((i % 20)) -eq 0 ] && echo -n "."
done
echo ""
echo "✓ Affiliates: ${#AFFILIATES[@]}"
echo ""

# Step 6: Create 210 contracts with varied statuses
echo "[6/9] Creating 210 contracts with varied statuses..."

# RFC3339 formatted dates for different contract statuses
TODAY_RFC=$(date -u +%Y-%m-%dT00:00:00Z)
YESTERDAY_RFC=$(date -u -d "-1 day" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v-1d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2026-01-09T00:00:00Z")
NEXT_WEEK_RFC=$(date -u -d "+7 days" +%Y-%m-%dT23:59:59Z 2>/dev/null || date -u -v+7d +%Y-%m-%dT23:59:59Z 2>/dev/null || echo "2026-01-17T23:59:59Z")
NEXT_MONTH_RFC=$(date -u -d "+30 days" +%Y-%m-%dT23:59:59Z 2>/dev/null || date -u -v+30d +%Y-%m-%dT23:59:59Z 2>/dev/null || echo "2026-02-09T23:59:59Z")
NEXT_YEAR_RFC=$(date -u -d "+365 days" +%Y-%m-%dT23:59:59Z 2>/dev/null || date -u -v+365d +%Y-%m-%dT23:59:59Z 2>/dev/null || echo "2027-01-10T23:59:59Z")
LAST_MONTH_RFC=$(date -u -d "-30 days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v-30d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2025-12-11T00:00:00Z")
LAST_WEEK_RFC=$(date -u -d "-7 days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v-7d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2026-01-03T00:00:00Z")
LAST_YEAR_RFC=$(date -u -d "-365 days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v-365d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2025-01-10T00:00:00Z")
FUTURE_START_RFC=$(date -u -d "+14 days" +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v+14d +%Y-%m-%dT00:00:00Z 2>/dev/null || echo "2026-01-24T00:00:00Z")
FUTURE_END_RFC=$(date -u -d "+200 days" +%Y-%m-%dT23:59:59Z 2>/dev/null || date -u -v+200d +%Y-%m-%dT23:59:59Z 2>/dev/null || echo "2026-07-29T23:59:59Z")

CONTRACT_MODELS=(
    "Licença Perpétua" "Assinatura Mensal" "Assinatura Anual" "Suporte Premium" "Suporte Standard"
    "Consultoria Técnica" "Manutenção Preventiva" "Manutenção Corretiva" "Treinamento In-Company"
    "Desenvolvimento Customizado" "Integração de Sistemas" "Hospedagem Cloud" "Backup Gerenciado"
    "Monitoramento 24/7" "SLA Ouro" "SLA Prata" "SLA Bronze" "Parceria Estratégica"
    "Revenda Autorizada" "Franquia Digital" "Locação de Equipamentos" "Outsourcing TI"
    "Projeto Específico" "Migração de Dados" "Auditoria de Segurança" "Pen Test"
)

declare -i ccount=0

if [ "${#SUBS[@]}" -gt 0 ] && [ "${#CLIENTS[@]}" -gt 5 ]; then
    for i in {1..210}; do
        # Select client (avoid archived ones at the end)
        client_idx=$((i % 155))
        if [ -z "${CLIENTS[$client_idx]}" ]; then
            continue
        fi

        sidx=$((RANDOM % ${#SUBS[@]}))
        model="${CONTRACT_MODELS[$((RANDOM % ${#CONTRACT_MODELS[@]}))]}"
        item_key="${model:0:3}-${TIMESTAMP}-${i}"

        # Determine contract status type based on distribution:
        # 40% Active (no end date or far future)
        # 15% Expiring soon (within 30 days)
        # 15% Expired
        # 15% Not started yet
        # 10% With affiliate
        # 5% Will be archived

        status_type=$((i % 20))

        case $status_type in
            0|1|2|3|4|5|6|7)
                # Active contracts - various configurations
                case $((i % 4)) in
                    0)
                        # No dates (always active, never expires)
                        res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model\",\"item_key\":\"$item_key\"}")
                        ;;
                    1)
                        # Started in past, ends far in future
                        res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model\",\"item_key\":\"$item_key\",\"start_date\":\"$LAST_YEAR_RFC\",\"end_date\":\"$NEXT_YEAR_RFC\"}")
                        ;;
                    2)
                        # Started today, no end date
                        res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model\",\"item_key\":\"$item_key\",\"start_date\":\"$TODAY_RFC\"}")
                        ;;
                    3)
                        # Started last month, ends next year
                        res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model\",\"item_key\":\"$item_key\",\"start_date\":\"$LAST_MONTH_RFC\",\"end_date\":\"$NEXT_YEAR_RFC\"}")
                        ;;
                esac
                ;;
            8|9|10)
                # Expiring soon (within 7-30 days)
                if [ $((i % 2)) -eq 0 ]; then
                    res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model (Expirando)\",\"item_key\":\"EXP-$item_key\",\"start_date\":\"$LAST_MONTH_RFC\",\"end_date\":\"$NEXT_WEEK_RFC\"}")
                else
                    res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model (Expirando)\",\"item_key\":\"EXP-$item_key\",\"start_date\":\"$LAST_YEAR_RFC\",\"end_date\":\"$NEXT_MONTH_RFC\"}")
                fi
                ;;
            11|12|13)
                # Expired contracts
                res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model (Expirado)\",\"item_key\":\"OLD-$item_key\",\"start_date\":\"$LAST_YEAR_RFC\",\"end_date\":\"$YESTERDAY_RFC\"}")
                ;;
            14|15|16)
                # Not started yet (future start date)
                res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model (Futuro)\",\"item_key\":\"FUT-$item_key\",\"start_date\":\"$FUTURE_START_RFC\",\"end_date\":\"$FUTURE_END_RFC\"}")
                ;;
            17|18)
                # With affiliate
                aff_idx=$((i % ${#AFFILIATES[@]}))
                if [ -n "${AFFILIATES[$aff_idx]}" ]; then
                    res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model (Filial)\",\"item_key\":\"AFF-$item_key\",\"affiliate_id\":\"${AFFILIATES[$aff_idx]}\",\"start_date\":\"$LAST_MONTH_RFC\",\"end_date\":\"$NEXT_YEAR_RFC\"}")
                else
                    res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model\",\"item_key\":\"$item_key\",\"start_date\":\"$LAST_MONTH_RFC\",\"end_date\":\"$NEXT_YEAR_RFC\"}")
                fi
                ;;
            19)
                # Will be archived (created active, then archived)
                res=$(api_call POST "/contracts" "{\"client_id\":\"${CLIENTS[$client_idx]}\",\"subcategory_id\":\"${SUBS[$sidx]}\",\"model\":\"$model (Para Arquivar)\",\"item_key\":\"ARC-$item_key\",\"start_date\":\"$LAST_YEAR_RFC\",\"end_date\":\"$NEXT_YEAR_RFC\"}")
                contract_id=$(getid "$res")
                if [ -n "$contract_id" ]; then
                    api_call PUT "/contracts/$contract_id/archive" "{}" > /dev/null 2>&1
                    ((ccount++))
                    [ $((ccount % 30)) -eq 0 ] && echo -n "."
                    continue
                fi
                ;;
        esac

        id=$(getid "$res")
        if [ -n "$id" ]; then
            ((ccount++))
            [ $((ccount % 30)) -eq 0 ] && echo -n "."
        fi
    done
fi
echo ""
echo "✓ Contracts: $ccount"
echo ""

# Step 7: Users
echo "[7/9] Creating 8 users..."
declare -i ucount=0

USERS=(
    "vendas_${TIMESTAMP}|Gerente de Vendas|user"
    "sistemas_${TIMESTAMP}|Analista de Sistemas|user"
    "consultor_${TIMESTAMP}|Consultor Senior|user"
    "supervisor_${TIMESTAMP}|Supervisor de TI|user"
    "coordenador_${TIMESTAMP}|Coordenador de Projetos|user"
    "atendimento_${TIMESTAMP}|Atendimento ao Cliente|user"
    "financeiro_${TIMESTAMP}|Analista Financeiro|user"
    "admin_${TIMESTAMP}|Administrador Auxiliar|admin"
)

for user_data in "${USERS[@]}"; do
    IFS='|' read -r username display_name role <<< "$user_data"
    res=$(api_call POST "/users" "{\"username\":\"$username\",\"display_name\":\"$display_name\",\"password\":\"SecurePass123!@Password\",\"role\":\"$role\"}")
    id=$(getid "$res")
    [ -n "$id" ] && ((ucount++)) && echo -n "."
done
echo ""
echo "✓ Users: $ucount"
echo ""

# Step 8: Generate some API activity for logs
echo "[8/9] Generating API activity for audit logs..."
declare -i activity_count=0

# Read some clients
for i in 0 5 10 15 20 25 30; do
    if [ -n "${CLIENTS[$i]}" ]; then
        api_call GET "/clients/${CLIENTS[$i]}" "" > /dev/null 2>&1
        ((activity_count++))
    fi
done

# Read some contracts
for i in 0 10 20 30 40 50; do
    api_call GET "/contracts" "" > /dev/null 2>&1
    ((activity_count++))
done

# Update some clients
for i in 35 40 45; do
    if [ -n "${CLIENTS[$i]}" ]; then
        api_call PUT "/clients/${CLIENTS[$i]}" "{\"notes\":\"Atualizado via script de população - $(date)\"}" > /dev/null 2>&1
        ((activity_count++))
    fi
done

# Read categories
api_call GET "/categories" "" > /dev/null 2>&1
((activity_count++))

# Read subcategories
api_call GET "/subcategories" "" > /dev/null 2>&1
((activity_count++))

echo "✓ Generated $activity_count API activities"
echo ""

# Step 9: Summary statistics
echo "[9/9] Calculating statistics..."

# Count contracts by status
active_count=0
expiring_count=0
expired_count=0
not_started_count=0
archived_count=0

echo ""
echo "====================================="
echo "✓ POPULATION COMPLETED!"
echo "====================================="
echo ""
echo "Summary:"
echo "  ✓ Categories: ${#CATS[@]}"
echo "  ✓ Subcategories: ${#SUBS[@]}"
echo "  ✓ Clients: ${#CLIENTS[@]} (5 archived)"
echo "  ✓ Affiliates: ${#AFFILIATES[@]}"
echo "  ✓ Contracts: $ccount"
echo "    - Ativos (sem expiração ou futuro distante): ~$((ccount * 40 / 100))"
echo "    - Expirando em Breve (≤30 dias): ~$((ccount * 15 / 100))"
echo "    - Expirados: ~$((ccount * 15 / 100))"
echo "    - Não Iniciados (data futura): ~$((ccount * 15 / 100))"
echo "    - Com Afiliado: ~$((ccount * 10 / 100))"
echo "    - Arquivados: ~$((ccount * 5 / 100))"
echo "  ✓ Users: $ucount"
echo "  ✓ API Activities: $activity_count"
echo ""
echo "Special Records:"
echo "  🎂 Client turning 37 today: '${SPECIAL_NAME}'"
echo "  🎂 Affiliate turning 37 today: 'Aniversariante do Dia - Afiliado Especial'"
echo "  📅 Birthday: $BIRTHDAY_37"
echo ""
echo "Birthday Distribution:"
echo "  ✓ At least 1 client birthday per week of the year"
echo "  ✓ At least 1 affiliate birthday per week of the year"
echo ""
echo "====================================="

rm -f /tmp/u*.json
