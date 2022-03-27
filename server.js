require('dotenv').config() 
const express = require ('express') 
const cors = require('cors'); 
const path  = require ('path') 
const bcrypt = require('bcryptjs') 
const jwt = require('jsonwebtoken') 

const app = express () 
 
app.use(cors()) 
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 

let checkToken = (req, res, next) => { 
  let authToken = req.headers["authorization"] 
  if (!authToken) {
      return res.status(401).json({ message: 'Token de acesso requerida' }) 
  } 
  else { 
      let token = authToken.split(' ')[1] 
      req.token = token 
  } 

  jwt.verify(req.token, process.env.SECRET_KEY, (err, decodeToken) => { 
      if (err) { 
          return res.status(401).json({ message: 'Acesso negado'}) 
      } 
      req.usuarioId = decodeToken.id 
      next() 
  }) 
} 

let isAdmin = (req, res, next) => { 
  knex 
      .select ('*').from ('usuario').where({ id: req.usuarioId }) 
      .then ((usuarios) => { 
          if (usuarios.length) { 
              let usuario = usuarios[0] 
              let roles = usuario.roles.split(';') 
              let adminRole = roles.find(i => i === 'ADMIN') 
              if (adminRole === 'ADMIN') { 
                  next() 
                  return 
              } 
              else { 
                  res.status(403).json({ message: 'Role de ADMIN requerida' }) 
                  return 
                } 
              } 
          }) 
          .catch (err => { 
              res.status(500).json({  
                message: 'Erro ao verificar roles de usuário - ' + err.message }) 
          }) 
  } 

const knex = require('knex')({ 
  client: 'pg', 
  debug: true, 
  connection: { 
      connectionString : process.env.DATABASE_URL, 
      ssl: { rejectUnauthorized: false }, 
    } 
}); 


app.get('/api/produtos/', checkToken, (req, res, next) => {
  knex.select('*')
  .from ('produto')
  .then(produtos => res.status(200).json(produtos))
})

app.get('/api/produtos/:id', checkToken, (req, res) => {
  const id = req.params.id
  knex.select('*')
  .from ('produto')
  .where({id: id})
  .then(produtos => {
    if(produtos.length){
      return res.status(200).json(produtos)
    }else{
      return res.status(404).json({message: 'produto nao encontrado'})
    }
  })
  .catch(err => res.status(500).json({message: 'ERRO AO RECUPERAR PRODUTO: '+err.message}))

})

app.delete('/api/produtos/:id', checkToken, isAdmin, (req, res) => {
  const id = req.params.id
  knex('produto')
  .where({id: id})
  .del()
  .then((n) => {
    if(n){
      return res.status(200).json({message: 'Produto excluido com sucesso'})

    }else{
      return res.status(200).json({message: 'Produto não encontrado'})
    }
  })
  .catch(err => res.status(500).json({message: 'ERRO AO EXCLUIR PRODUTO: '+err.message}))

})

app.post('/api/produtos/', checkToken, isAdmin, (req, res) => {
  const product = {...req.body}
  knex('produto')
  .insert(product)
  .then(()=>{
    return res.status(200).json({message: 'Produto inserido com sucesso'})
  })
  .catch(err => res.status(500).json({message: 'ERRO AO INSERIR PRODUTO: '+err.message}))
})

app.put('/api/produtos/:id', checkToken, isAdmin, (req, res) => {
  
  const id = req.params.id
  const product = {...req.body}

  knex('produto')
  .update(product)
  .where({id})
  .then(()=>{
    return res.status(200).json({message: 'Produto alterado com sucesso'})
  })
  .catch(err => res.status(500).json({message: 'ERRO AO ALTERAR PRODUTO: '+err.message}))

})

app.post ('/seguranca/register', (req, res) => { 
  knex ('usuario') 
      .insert({ 
          nome: req.body.nome,  
          login: req.body.login,  
          senha: bcrypt.hashSync(req.body.senha, 8),  
          email: req.body.email 
      }, ['id', 'nome', 'email', 'login', 'roles']) 
      .then((result) => { 
          let usuario = result[0] 
          res.status(200).json({
            "id": usuario.id,
            "nome": usuario.nome,
            "email": usuario.email,
            "login": usuario.login,
            "roles": usuario.roles,
          })
          return 
      }) 
      .catch(err => { 
          res.status(500).json({  
              message: 'Erro ao registrar usuario - ' + err.message }) 
      })   
}) 

app.post('/seguranca/login', (req, res) => {  
  knex 
    .select('*').from('usuario').where( { login: req.body.login }) 
    .then( usuarios => { 
        if(usuarios.length){ 
            let usuario = usuarios[0] 
            let checkSenha = bcrypt.compareSync (req.body.senha, usuario.senha) 
            if (checkSenha) { 
               var tokenJWT = jwt.sign({ id: usuario.id },  
                    process.env.SECRET_KEY, { 
                      expiresIn: 3600 
                    }) 

                res.status(200).json ({ 
                    id: usuario.id, 
                    login: usuario.login,  
                    nome: usuario.nome,  
                    roles: usuario.roles, 
                    token: tokenJWT 
                })   
                return  
            } 
        }  
           
        res.status(200).json({ message: 'Login ou senha incorretos' }) 
    }) 
    .catch (err => { 
        res.status(500).json({  
           message: 'Erro ao verificar login - ' + err.message }) 
    }) 
}) 

app.use('/app', express.static (path.join (__dirname, '/public'))) 


let port = process.env.PORT || 3000 
app.listen (port) 