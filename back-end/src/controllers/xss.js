import prisma from '../database/client.js'
import sanitizeHtml from 'sanitize-html' // Biblioteca recomendada para Node.js

const controller = {}

controller.retrieveComments = async function(req, res) {
  try {
    const comments = await prisma.xssComment.findMany({
      orderBy: { id: 'asc' }
    })

    res.send(comments)
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.createComment = async function(req, res) {
  try {
    const rawContent = req.body?.content ?? ''

    // Sanitiza o conteúdo removendo scripts maliciosos e tags perigosas.
    // Se o campo aceitar apenas texto puro, você pode configurar allowedTags: [].
    const sanitizedContent = sanitizeHtml(rawContent, {
      allowedTags: [],          // Remove todas as tags HTML (converte para texto puro seguro)
      allowedAttributes: {}     // Remove todos os atributos (como onclick, onerror, etc.)
    })

    await prisma.xssComment.create({
      data: { content: sanitizedContent }
    })

    res.status(201).end()
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

export default controller