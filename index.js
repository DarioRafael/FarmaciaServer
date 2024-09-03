require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;



const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: true,
    connectTimeout: 30000,
  },
};

app.use(cors({
  origin: 'https://moderna-shop-dch54tpat-dariorafaels-projects.vercel.app', // Reemplaza con tu dominio específico
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true
}));

app.use(express.json());

app.post('/api/v1/ingresar', async (req, res) => {
  const { email, password } = req.body;
  console.log('Petición de inicio de sesión recibida:', { email, password });

  try {
    const pool = await sql.connect(config);
    const request = pool.request();
    const result = await request
      .input('correo', sql.VarChar, email)
      .input('contraseña', sql.VarChar, password)
      .query('SELECT * FROM Trabajadores WHERE correo = @correo AND contraseña = @contraseña');

    if (result.recordset.length > 0) {
      res.status(200).send('Login successful');
    } else {
      res.status(401).send('Invalid email or password');
    }
  } catch (err) {
    console.error('Connection failed:', err);
    res.status(500).send('Server error');
  }
});


// Nueva ruta para obtener todos los trabajadores
app.get('/api/v1/trabajadores', async (req, res) => {
  console.log('Petición para obtener todos los trabajadores recibida');

  try {
    const pool = await sql.connect(config);
    const request = pool.request();
    const result = await request.query('SELECT * FROM Trabajadores');

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error('Error al obtener los trabajadores:', err);
    res.status(500).send('Server error');
  }
});



// Añadir esta línea para iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor en ejecución en el puerto ${port}`);
});





module.exports = app;
