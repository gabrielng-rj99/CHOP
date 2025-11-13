import React, { useState, useEffect } from 'react'

export default function Clients({ token, apiUrl }) {
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    loadClients()
  }, [])

  const loadClients = async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${apiUrl}/api/clients`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error('Erro ao carregar clientes')
      }

      const data = await response.json()
      setClients(data.data || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString) => {
    if (!dateString) return '-'
    const date = new Date(dateString)
    return date.toLocaleDateString('pt-BR')
  }

  const filteredClients = clients.filter(client => {
    if (filter === 'active') return !client.archived_at && client.status === 'ativo'
    if (filter === 'archived') return !!client.archived_at
    return !client.archived_at
  })

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '60px' }}>
        <div style={{ fontSize: '18px', color: '#7f8c8d' }}>Carregando clientes...</div>
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
          onClick={loadClients}
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
        <h1 style={{ fontSize: '32px', color: '#2c3e50', margin: 0 }}>Clientes</h1>
        <button
          onClick={loadClients}
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
          Todos ({clients.filter(c => !c.archived_at).length})
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
          onClick={() => setFilter('archived')}
          style={{
            padding: '8px 16px',
            background: filter === 'archived' ? '#95a5a6' : 'white',
            color: filter === 'archived' ? 'white' : '#2c3e50',
            border: '1px solid #ddd',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          Arquivados
        </button>
      </div>

      <div style={{
        background: 'white',
        borderRadius: '8px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        border: '1px solid #ecf0f1',
        overflow: 'hidden'
      }}>
        {filteredClients.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#7f8c8d' }}>
            Nenhum cliente encontrado
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f8f9fa', borderBottom: '2px solid #ecf0f1' }}>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  NOME
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  CPF/CNPJ
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  EMAIL
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  TELEFONE
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  STATUS
                </th>
                <th style={{ padding: '16px', textAlign: 'left', fontSize: '13px', fontWeight: '600', color: '#7f8c8d' }}>
                  CADASTRO
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredClients.map((client) => {
                const statusColor = client.status === 'ativo' ? '#27ae60' : '#95a5a6'
                return (
                  <tr key={client.id} style={{ borderBottom: '1px solid #ecf0f1' }}>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#2c3e50', fontWeight: '500' }}>
                      {client.name}
                      {client.nickname && (
                        <div style={{ fontSize: '12px', color: '#7f8c8d', fontWeight: 'normal' }}>
                          {client.nickname}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d', fontFamily: 'monospace' }}>
                      {client.registration_id || '-'}
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d' }}>
                      {client.email || '-'}
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d' }}>
                      {client.phone || '-'}
                    </td>
                    <td style={{ padding: '16px' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '4px 12px',
                        borderRadius: '12px',
                        fontSize: '12px',
                        fontWeight: '600',
                        background: statusColor + '20',
                        color: statusColor,
                        textTransform: 'capitalize'
                      }}>
                        {client.status}
                      </span>
                    </td>
                    <td style={{ padding: '16px', fontSize: '14px', color: '#7f8c8d' }}>
                      {formatDate(client.created_at)}
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
