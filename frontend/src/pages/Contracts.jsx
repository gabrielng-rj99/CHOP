import React, { useState, useEffect } from 'react'

export default function Contracts({ token, apiUrl }) {
  const [contracts, setContracts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    loadContracts()
  }, [])

  const loadContracts = async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${apiUrl}/api/contracts`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error('Erro ao carregar contratos')
      }

      const data = await response.json()
      setContracts(data.data || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const getContractStatus = (contract) => {
    const endDate = new Date(contract.end_date)
    const now = new Date()
    const daysUntilExpiration = Math.ceil((endDate - now) / (1000 * 60 * 60 * 24))

    if (daysUntilExpiration < 0) {
      return { status: 'Expirado', color: '#e74c3c' }
    } else if (daysUntilExpiration <= 30) {
      return { status: 'Expirando', color: '#f39c12' }
    } else {
      return { status: 'Ativo', color: '#27ae60' }
    }
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('pt-BR')
  }

  const filteredContracts = contracts.filter(contract => {
    if (contract.archived_at) return false

    const status = getContractStatus(contract)

    if (filter === 'active') return status.status === 'Ativo'
    if (filter === 'expiring') return status.status === 'Expirando'
    if (filter === 'expired') return status.status === 'Expirado'
    return true
  })

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '60px' }}>
        <div style={{ fontSize: '18px', color: '#7f8c8d' }}>Carregando contratos...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div style={{ padding: '20px' }}>
        <div style={{
          background: '#fee',
          color: '#c33',
          padding: '16px',
          borderRadius: '4px',
          border: '1px solid #fcc'
        }}>
          {error}
        </div>
        <button
          onClick={loadContracts}
          style={{
            marginTop: '16px',
            padding: '10px 20px',
            background: '#3498db',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Tentar Novamente
        </button>
      </div>
    )
  }

  return (
    <div>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '30px'
      }}>
        <h1 style={{ fontSize: '32px', color: '#2c3e50', margin: 0 }}>Contratos</h1>
        <button
          onClick={loadContracts}
          style={{
            padding: '10px 20px',
            background: '#3498db',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          Atualizar
        </button>
      </div>

      <div style={{
        display: 'flex',
        gap: '12px',
        marginBottom: '24px',
        flexWrap: 'wrap'
      }}>
        <button
          onClick={() => setFilter('all')}
          style={{
            padding: '8px 16px',
            background: filter === 'all' ? '#3498db' : 'white',
            color: filter === 'all' ? 'white' : '#2c3e50',
            border: '1px solid #ddd',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          Todos ({contracts.filter(c => !c.archived_at).length})
        </button>
        <button
          onClick={() => setFilter('active')}
          style={{
            padding: '8px 16px',
            background: filter === 'active' ? '#27ae60' : 'white',
            color: filter === 'active' ? 'white' : '#2c3e50',
            border: '1px solid #ddd',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          Ativos
        </button>
        <button
          onClick={() => setFilter('expiring')}
          style={{
            padding: '8px 16px',
            background: filter === 'expiring' ? '#f39c12' : 'white',
            color: filter === 'expiring' ? 'white' : '#2c3e50',
            border: '1px solid #ddd',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          Expirando
        </button>
        <button
          onClick={() => setFilter('expired')}
          style={{
            padding: '8px 16px',
            background: filter === 'expired' ? '#e74c3c' : 'white',
            color: filter === 'expired' ? 'white' : '#2c3e50',
            border: '1px solid #ddd',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          Expirados
        </button>
      </div>

      <div style={{
        background: 'white',
        borderRadius: '8px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        border: '1px solid #ecf0f1',
        overflow: 'hidden'
      }}>
        {filteredContracts.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#7f8c8d' }}>
            Nenhum contrato encontrado
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f8f9fa', borderBottom: '2px solid #ecf0f1' }}>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  MODELO
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  CHAVE DO PRODUTO
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  DATA INÍCIO
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  DATA FIM
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  STATUS
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredContracts.map((contract) => {
                const status = getContractStatus(contract)
                return (
                  <tr key={contract.id} style={{ borderBottom: '1px solid #ecf0f1' }}>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#2c3e50' }}>
                      {contract.model}
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d', fontFamily: 'monospace' }}>
                      {contract.product_key}
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d' }}>
                      {formatDate(contract.start_date)}
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d' }}>
                      {formatDate(contract.end_date)}
                    </td>
                    <td style={{ padding: '16px' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '4px 12px',
                        borderRadius: '12px',
                        fontSize: '12px',
                        fontWeight: '600',
                        background: status.color + '20',
                        color: status.color
                      }}>
                        {status.status}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
