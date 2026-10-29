
import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import argon2 from 'argon2'

const hashOptions = {
  type: argon2.argon2id,
  memoryCost: 66560,
  timeCost: 3,
  parallelism: 4
}

const controller = {}

// Gera o hash da senha utilizando Argon2id
async function hashPassword(password) {
  return argon2.hash(password, hashOptions)
}

// Remove a senha do objeto antes de retornar dados
function sanitizeUser(user) {
  if (!user) return null

  const { password, ...safeUser } = user
  return safeUser
}

// Criação de usuário
controller.create = async function(req, res) {
  try {
    const { fullname, username, email, password } = req.body ?? {}

    if (
      typeof fullname !== 'string' ||
      typeof username !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !fullname.trim() ||
      !username.trim() ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: 'Preencha nome, usuário, email e senha.'
      })
    }

    const hashedPassword = await hashPassword(password)

    const user = await prisma.user.create({
      data: {
        fullname,
        username,
        email,
        password: hashedPassword
      },
      select: {
        id: true,
        fullname: true,
        username: true,
        email: true,
        is_admin: true
      }
    })

    return res.status(201).json(user)
  }
  catch (error) {
    if (error?.code === 'P2002') {
      return res.status(409).json({
        error: 'Usuário ou email já cadastrado.'
      })
    }

    console.error('Erro ao criar usuário:', error)
    return res.status(500).json({
      error: 'Erro interno ao criar usuário.'
    })
  }
}

// Listagem de usuários
controller.retrieveAll = async function(req, res) {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        fullname: true,
        username: true,
        email: true,
        is_admin: true
      }
    })

    return res.status(200).json(users)
  }
  catch (error) {
    console.error('Erro ao listar usuários:', error)
    return res.status(500).json({
      error: 'Erro interno ao listar usuários.'
    })
  }
}

// Busca de um usuário por ID
controller.retrieveOne = async function(req, res) {
  try {
    const id = Number(req.params.id)

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({
        error: 'ID de usuário inválido.'
      })
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        fullname: true,
        username: true,
        email: true,
        is_admin: true
      }
    })

    if (!user) {
      return res.status(404).json({
        error: 'Usuário não encontrado.'
      })
    }

    return res.status(200).json(user)
  }
  catch (error) {
    console.error('Erro ao buscar usuário:', error)
    return res.status(500).json({
      error: 'Erro interno ao buscar usuário.'
    })
  }
}

// Atualização de usuário
controller.update = async function(req, res) {
  try {
    const id = Number(req.params.id)

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({
        error: 'ID de usuário inválido.'
      })
    }

    const { fullname, username, email, password } = req.body ?? {}
    const data = {}

    if (fullname !== undefined) data.fullname = fullname
    if (username !== undefined) data.username = username
    if (email !== undefined) data.email = email

    // Só gera um novo hash quando uma nova senha é informada
    if (password !== undefined) {
      if (typeof password !== 'string' || password.length === 0) {
        return res.status(400).json({
          error: 'A nova senha é inválida.'
        })
      }

      data.password = await hashPassword(password)
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({
        error: 'Nenhum campo válido foi informado para atualização.'
      })
    }

    const user = await prisma.user.update({
      where: { id },
      data,
      select: {
        id: true,
        fullname: true,
        username: true,
        email: true,
        is_admin: true
      }
    })

    return res.status(200).json(user)
  }
  catch (error) {
    if (error?.code === 'P2025') {
      return res.status(404).json({
        error: 'Usuário não encontrado.'
      })
    }

    if (error?.code === 'P2002') {
      return res.status(409).json({
        error: 'Usuário ou email já cadastrado.'
      })
    }

    console.error('Erro ao atualizar usuário:', error)
    return res.status(500).json({
      error: 'Erro interno ao atualizar usuário.'
    })
  }
}

// Exclusão de usuário
controller.delete = async function(req, res) {
  try {
    const id = Number(req.params.id)

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({
        error: 'ID de usuário inválido.'
      })
    }

    await prisma.user.delete({
      where: { id }
    })

    return res.status(204).end()
  }
  catch (error) {
    if (error?.code === 'P2025') {
      return res.status(404).json({
        error: 'Usuário não encontrado.'
      })
    }

    console.error('Erro ao excluir usuário:', error)
    return res.status(500).json({
      error: 'Erro interno ao excluir usuário.'
    })
  }
}

// Login
controller.login = async function(req, res) {
  try {
    const { username, email, password } = req.body ?? {}

    if (
      typeof password !== 'string' ||
      (!username && !email)
    ) {
      return res.status(400).json({
        error: 'Informe usuário ou email e senha.'
      })
    }

    const conditions = []

    if (typeof username === 'string' && username.length > 0) {
      conditions.push({ username })
    }

    if (typeof email === 'string' && email.length > 0) {
      conditions.push({ email })
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: conditions
      }
    })

    if (!user) {
      return res.status(401).json({
        error: 'Usuário ou senha inválidos.'
      })
    }

    // Verifica se a senha armazenada possui formato Argon2id.
    // Contas antigas precisam ter a senha redefinida para esse formato.
    if (
      typeof user.password !== 'string' ||
      !user.password.startsWith('$argon2id$')
    ) {
      console.error(
        'A conta possui senha armazenada fora do formato Argon2id.'
      )

      return res.status(401).json({
        error: 'Credenciais inválidas. Redefina a senha da conta.'
      })
    }

    const passwordIsValid = await argon2.verify(
      user.password,
      password
    )

    if (!passwordIsValid) {
      return res.status(401).json({
        error: 'Usuário ou senha inválidos.'
      })
    }

    const safeUser = sanitizeUser(user)

    if (!process.env.TOKEN_SECRET) {
      console.error('TOKEN_SECRET não configurado.')
      return res.status(500).json({
        error: 'Configuração de autenticação inválida.'
      })
    }

    const token = jwt.sign(
      safeUser,
      process.env.TOKEN_SECRET,
      { expiresIn: '24h' }
    )

    const cookieName = process.env.AUTH_COOKIE_NAME

    if (cookieName) {
      res.cookie(cookieName, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 1000
      })
    }

    return res.status(200).json({
      token,
      user: safeUser
    })
  }
  catch (error) {
    console.error('Erro no login:', error)

    return res.status(500).json({
      error: 'Erro interno durante a autenticação.'
    })
  }
}

// Informações do usuário autenticado
controller.me = function(req, res) {
  if (!req.authUser) {
    return res.status(401).json({
      error: 'Usuário não autenticado.'
    })
  }

  return res.status(200).json(sanitizeUser(req.authUser))
}

export default controller
