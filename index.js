require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const bcrypt = require('bcrypt');
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

const allowedOrigins = [
  'https://moderna-shop-dch54tpat-dariorafaels-projects.vercel.app',
  'https://moderna-shop-app.vercel.app',
  'https://moderna-shop-app.vercel.app/#/login',
  'https://moderna-shop-app.vercel.app/login'
];

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.use(express.json());

app.post('/api/v1/ingresar', async (req, res) => {
  console.log('Headers:', req.headers);
  console.log('Body:', req.body);

  const { email, password } = req.body;
  console.log('Petición de inicio de sesión recibida:', { email, password });

  try {
    const pool = await sql.connect(config);
    const request = pool.request();
    const result = await request
        .input('correo', sql.VarChar, email)
        .query('SELECT contraseña FROM Trabajadores WHERE correo = @correo');

    if (result.recordset.length > 0) {
      const hashedPassword = result.recordset[0].contraseña;
      const isMatch = await bcrypt.compare(password, hashedPassword);
      if (isMatch) {
        res.status(200).send('Login successful');
      } else {
        res.status(401).send('Invalid email or password');
      }
    } else {
      res.status(401).send('Invalid email or password');
    }
  } catch (err) {
    console.error('Connection failed:', err);
    res.status(500).send('Server error');
  }
});

app.get('/api/v1/trabajadores', async (req, res) => {
  console.log('Petición para obtener todos los trabajadores recibida');

  try {
    const pool = await sql.connect(config);
    const request = pool.request();
    const result = await request.query('SELECT id, nombre, correo FROM Trabajadores');

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error('Error al obtener los trabajadores:', err);
    res.status(500).send('Server error');
  }
});

app.listen(port, () => {
  console.log(`Servidor en ejecución en el puerto ${port}`);
});

module.exports = app;