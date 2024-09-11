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
    'https://modelo-shop-dch54tpat-dariorafaels-projects.vercel.app',
    'https://modelo-shop-app.vercel.app',
    'https://modelo-shop-app.vercel.app/#/login',
    'https://modelo-shop-app.vercel.app/login',
    'https://modelo-shop-app-git-main-dariorafaels-projects.vercel.app/'
];

app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));


app.use(express.json());

app.post('/api/v1/ingresar', async (req, res) => {
    const {email, password} = req.body;

    try {
        const pool = await sql.connect(config);
        const request = pool.request();
        const result = await request
            .input('correo', sql.VarChar, email)
            .query('SELECT * FROM Trabajadores WHERE correo = @correo');

        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            const match = await bcrypt.compare(password, user.contraseña);

            if (match) {
                res.status(200).send('Login successful');
            } else {
                res.status(401).send('Invalid email or password');
            }
        } else {
            res.status(401).send('Invalid email or password');
        }
    } catch (err) {
        console.error('Error al iniciar sesión:', err.message);
        res.status(500).send('Server error');
    }
});

//Register
app.post('/api/v1/registrar', async (req, res) => {
    const {nombre, correo, password, rol} = req.body;

    if (!nombre || !correo || !password || !rol) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        const pool = await sql.connect(config);

        // Verificar si el correo ya está registrado
        const existingUser = await pool.request()
            .input('correo', sql.VarChar, correo)
            .query('SELECT * FROM Trabajadores WHERE correo = @correo');

        if (existingUser.recordset.length > 0) {
            return res.status(400).send('El correo ya está registrado.');
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar el nuevo usuario en la base de datos
        await pool.request()
            .input('nombre', sql.VarChar, nombre)
            .input('correo', sql.VarChar, correo)
            .input('contraseña', sql.VarChar, hashedPassword)
            .input('rol', sql.VarChar, rol)
            .input('fecha_creacion', sql.DateTime, new Date())
            .input('estado', sql.VarChar, 'activo')
            .query('INSERT INTO Trabajadores (nombre, correo, contraseña, rol, fecha_creacion, estado) VALUES (@nombre, @correo, @contraseña, @rol, @fecha_creacion, @estado)');

        res.status(201).send('Usuario registrado correctamente.');
    } catch (err) {
        console.error('Error al registrar usuario:', err.message);
        res.status(500).send('Error al registrar usuario.');
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


app.post('/api/v1/actualizar-contrasenas', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        // Obtener todas las contraseñas de la tabla Trabajadores
        const request = pool.request();
        const result = await request.query('SELECT id, contraseña FROM Trabajadores');

        // Iniciar una transacción
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        for (const user of result.recordset) {
            if (user.contraseña) {
                const hashedPassword = await bcrypt.hash(user.contraseña, 10);

                // Crear una nueva solicitud para cada consulta dentro de la transacción
                const transactionRequest = new sql.Request(transaction);

                await transactionRequest
                    .input('id', sql.Int, user.id)
                    .input('contraseña', sql.VarChar, hashedPassword)
                    .query('UPDATE Trabajadores SET contraseña = @contraseña WHERE id = @id');
            }
        }

        // Confirmar la transacción
        await transaction.commit();

        res.status(200).send('Contraseñas actualizadas correctamente.');
    } catch (err) {
        console.error('Error al actualizar contraseñas:', err.message);

        // Manejo de errores y revertir la transacción si es necesario
        if (transaction) {
            try {
                await transaction.rollback();
            } catch (rollbackErr) {
                console.error('Error al revertir la transacción:', rollbackErr.message);
            }
        }

        res.status(500).send('Error al actualizar contraseñas.');
    }
});


// Añadir esta línea para iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});


module.exports = app;
