require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');



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
    const result = await request.query('SELECT id, nombre, correo FROM Trabajadores');

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error('Error al obtener los trabajadores:', err);
    res.status(500).send('Server error');
  }
});



app.post('/api/v1/actualizar-contraseñas', async (req, res) => {
  try {
    // Conectar al pool de base de datos
    const pool = await sql.connect(config);
    const request = pool.request();

    // Obtener todas las contraseñas de la tabla Trabajadores
    const result = await request.query('SELECT id, contraseña FROM Trabajadores');

    // Iniciar una transacción
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    // Preparar una nueva consulta dentro de la transacción
    const transactionRequest = new sql.Request(transaction);

    for (const user of result.recordset) {
      const hashedPassword = await bcrypt.hash(user.contraseña, 10);
      await transactionRequest
          .input('id', sql.Int, user.id)
          .input('contraseña', sql.VarChar, hashedPassword)
          .query('UPDATE Trabajadores SET contraseña = @contraseña WHERE id = @id');
    }

    // Confirmar la transacción
    await transaction.commit();

    // Responder con éxito
    res.status(200).send('Contraseñas actualizadas correctamente.');
  } catch (err) {
    console.error('Error al actualizar contraseñas:', err);

    // Manejo de errores y revertir la transacción si es necesario
    if (transaction) {
      await transaction.rollback();
    }

    res.status(500).send('Error al actualizar contraseñas.');
  }
});




// Añadir esta línea para iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor en ejecución en el puerto ${port}`);
});





module.exports = app;
