import prisma from '../database/client.js'

const controller = {}

controller.login = async function(req, res) {
  const username = req.body?.username ?? ''
  const password = req.body?.password ?? ''

  try {
    // Consulta parametrizada: os valores são tratados como dados,
    // e não como parte do comando SQL.
    const users = await prisma.$queryRaw`
      SELECT * FROM "User"
      WHERE username = ${username}
      AND password = ${password}
    `

    if (users.length > 0) {
      return res.send({
        success: true,
        message: `Bem-vindo, ${username}!`,
        result: users
      })
    }

    return res.status(401).send({
      success: false,
      message: 'Login falhou!'
    })
  } catch (error) {
    console.error('Erro ao realizar login:', error)

    return res.status(500).send({
      success: false,
      message: 'Erro no servidor'
    })
  }
}

export default controller

