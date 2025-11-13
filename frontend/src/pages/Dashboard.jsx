import React, { useState, useEffect } from 'react'

export default function Dashboard({ token, apiUrl }) {
  const [contracts, setContracts] = useState([])
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    setError('')

    try {
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }

      const [contractsRes, clientsRes] = await Promise.all([
        fetch(`${apiUrl}/api/contracts`, { headers }),
        fetch(`${apiUrl}/api/clients`, { headers })
      ])

      if (!contractsRes.ok || !clientsRes.ok) {
        throw new Error('Erro ao carregar dados')
      }

      const contractsData = await contractsRes.json()
      const clientsData = await clientsRes.json()

      setContracts(contractsData.data || [])
      setClients(clientsData.data || [])
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

  const activeContracts = contracts.filter(c => {
    const status = getContractStatus(c)
    return !c.archived_at && status.status === 'Ativo'
  })

  const expiringContracts = contracts.filter(c => {
    const status = getContractStatus(c)
    return !c.archived_at && status.status === 'Expirando'
  })

  const expiredContracts = contracts.filter(c => {
    const status = getContractStatus(c)
    return !c.archived_at && status.status === 'Expirado'
  })

  const activeClients = clients.filter(c => !c.archived_at && c.status === 'ativo')

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '60px' }}>
        <div style={{ fontSize: '18px', color: '#7f8c8d' }}>Carregando...</div>
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
          onClick={loadData}
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
      <h1 style={{ fontSize: '32px', marginBottom: '30px', color: '#2c3e50' }}>Dashboard</h1>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '20px',
        marginBottom: '40px'
      }}>
        <div style={{
          background: 'white',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          border: '1px solid #ecf0f1'
        }}>
          <div style={{ color: '#7f8c8d', fontSize: '14px', marginBottom: '8px' }}>Contratos Ativos</div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#27ae60' }}>
            {activeContracts.length}
          </div>
        </div>

        <div style={{
          background: 'white',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          border: '1px solid #ecf0f1'
        }}>
          <div style={{ color: '#7f8c8d', fontSize: '14px', marginBottom: '8px' }}>Expirando em Breve</div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#f39c12' }}>
            {expiringContracts.length}
          </div>
        </div>

        <div style={{
          background: 'white',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          border: '1px solid #ecf0f1'
        }}>
          <div style={{ color: '#7f8c8d', fontSize: '14px', marginBottom: '8px' }}>Contratos Expirados</div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#e74c3c' }}>
            {expiredContracts.length}
          </div>
        </div>

        <div style={{
          background: 'white',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          border: '1px solid #ecf0f1'
        }}>
          <div style={{ color: '#7f8c8d', fontSize: '14px', marginBottom: '8px' }}>Clientes Ativos</div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#3498db' }}>
            {activeClients.length}
          </div>
        </div>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: '20px'
      }}>
        <div style={{
          background: 'white',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          border: '1px solid #ecf0f1'
        }}>
          <h2 style={{ fontSize: '20px', marginBottom: '20px', color: '#2c3e50' }}>
            Contratos Expirando em Breve
          </h2>
          {expiringContracts.length === 0 ? (
            <p style={{ color: '#7f8c8d', fontSize: '14px' }}>Nenhum contrato expirando</p>
          ) : (
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              {expiringContracts.slice(0, 5).map(contract => {
                const endDate = new Date(contract.end_date)
                const now = new Date()
                const daysLeft = Math.ceil((endDate - now) / (1000 * 60 * 60 * 24))

                return (
                  <div key={contract.id} style={{
                    padding: '12px',
                    background: '#fff9e6',
                    borderRadius: '4px',
                    marginBottom: '8px',
                    border: '1px solid #ffe6b3'
                  }}>
                    <div style={{ fontWeight: '600', color: '#2c3e50', marginBottom: '4px' }}>
                      {contract.model}
                    </div>
                    <div style={{ fontSize: '13px', color: '#7f8c8d' }}>
                      {contract.product_key}
                    </div>
                    <div style={{
                      marginTop: '8px',
                      fontSize: '12px',
                      color: '#f39c12',
                      fontWeight: '600'
                    }}>
                      {daysLeft} dias restantes
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div style={{
          background: 'white',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          border: '1px solid #ecf0f1'
        }}>
          <h2 style={{ fontSize: '20px', marginBottom: '20px', color: '#2c3e50' }}>
            Contratos Expirados
          </h2>
          {expiredContracts.length === 0 ? (
            <p style={{ color: '#7f8c8d', fontSize: '14px' }}>Nenhum contrato expirado</p>
          ) : (
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              {expiredContracts.slice(0, 5).map(contract => {
                const endDate = new Date(contract.end_date)
                const now = new Date()
                const daysExpired = Math.ceil((now - endDate) / (1000 * 60 * 60 * 24))

                return (
                  <div key={contract.id} style={{
                    padding: '12px',
                    background: '#ffe6e6',
                    borderRadius: '4px',
                    marginBottom: '8px',
                    border: '1px solid #ffcccc'
                  }}>
                    <div style={{ fontWeight: '600', color: '#2c3e50', marginBottom: '4px' }}>
                      {contract.model}
                    </div>
                    <div style={{ fontSize: '13px', color: '#7f8c8d' }}>
                      {contract.product_key}
                    </div>
                    <div style={{
                      marginTop: '8px',
                      fontSize: '12px',
                      color: '#e74c3c',
                      fontWeight: '600'
                    }}>
                      Expirado há {daysExpired} dias
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
