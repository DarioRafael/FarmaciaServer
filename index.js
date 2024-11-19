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
    'https://modelo-shop-app-git-main-dariorafaels-projects.vercel.app/',
    /^http:\/\/localhost:\d+$/ // Acepta cualquier puerto en localhost
];
//
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.some(o => typeof o === 'string' ? o === origin : o.test(origin))) {
            callback(null, true);
        } else {
            callback(new Error('Origen no permitido por CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));



app.use(express.json());

app.post('/api/v1/ingresar', async (req, res) => {
    const { email, password } = req.body;

    try {
        const pool = await sql.connect(config);
        const request = pool.request();
        const result = await request
            .input('correo', sql.VarChar, email)
            .query('SELECT * FROM Trabajadores WHERE correo = @correo');

        if (result.recordset.length > 0) {
            const user = result.recordset[0];

            // Verificar el estado del usuario
            if (user.estado !== 'activo') {
                return res.status(403).send('Acceso denegado: el usuario está inactivo.');
            }

            const match = await bcrypt.compare(password, user.contraseña);

            if (match) {
                res.status(200).json({
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        nombre: user.nombre,
                        correo: user.correo,
                        rol: user.rol, // Devuelve el rol
                    },
                });
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


const authorizeRole = (roles) => {
    return (req, res, next) => {
        const userRole = req.user.rol; // Asegúrate de que el rol del usuario esté disponible en el req.user

        if (roles.includes(userRole)) {
            return next();
        } else {
            return res.status(403).send('No tienes permisos para acceder a esta ruta.');
        }
    };
};

// Por ejemplo, si tienes una ruta que solo debe ser accesible por administradores
app.get('/api/v1/admin', authorizeRole(['admin']), (req, res) => {
    res.status(200).send('Acceso a administrador concedido.');
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


app.get('/api/v1/trabajadores', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT id, nombre, correo, rol, fecha_creacion, estado FROM Trabajadores');

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener trabajadores:', err);
        res.status(500).send('Error del servidor al obtener trabajadores');
    }
});

// Endpoint para eliminar un trabajador
app.delete('/api/v1/trabajadores/:id/eliminar', async (req, res) => {
    const { id } = req.params;

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM Trabajadores WHERE id = @id');

        if (result.rowsAffected[0] > 0) {
            res.status(200).send('Trabajador eliminado exitosamente.');
        } else {
            res.status(404).send('Trabajador no encontrado.');
        }
    } catch (err) {
        console.error('Error al eliminar trabajador:', err);
        res.status(500).send('Error del servidor al eliminar trabajador.');
    }
});



app.delete('/api/v1/trabajadores/:id', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('UPDATE Trabajadores SET estado = \'inactivo\' WHERE id = @id');

        res.status(200).send('Trabajador desactivado exitosamente');
    } catch (err) {
        console.error('Error al desactivar trabajador:', err);
        res.status(500).send('Error del servidor al desactivar trabajador');
    }
});

// Endpoint para actualizar el estado de un trabajador
app.patch('/api/v1/trabajadores/:id/estado', async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    // Validar que 'estado' esté presente y sea 'activo' o 'inactivo'
    if (!estado || !['activo', 'inactivo'].includes(estado.toLowerCase())) {
        return res.status(400).send("Estado inválido. Debe ser 'activo' o 'inactivo'.");
    }

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('id', sql.Int, id)
            .input('estado', sql.VarChar, estado.toLowerCase())
            .query('UPDATE Trabajadores SET estado = @estado WHERE id = @id');

        if (result.rowsAffected[0] > 0) {
            res.status(200).json({ message: `Estado del trabajador actualizado a '${estado}'.` });
        } else {
            res.status(404).send('Trabajador no encontrado.');
        }
    } catch (err) {
        console.error('Error al actualizar estado del trabajador:', err);
        res.status(500).send('Error del servidor al actualizar estado del trabajador.');
    }
});

app.get('/api/v1/keepalive', (req, res) => {
    res.status(200).send('Server is alive!');
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

app.get('/api/v1/categorias', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT C.IDCategoria,C.Nombre FROM Categoria C;');

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener categorias:', err);
        res.status(500).send('Error del servidor al obtener categorias');
    }
});


app.get('/api/v1/productos', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT P.IDProductos,P.Nombre,Categoria = (SELECT C.Nombre FROM Categoria C WHERE P.IDCategoria = C.IDCategoria),P.Stock,P.Precio,P.PrecioDeCompra FROM Productos P;');

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener productos:', err);
        res.status(500).send('Error del servidor al obtener productos');
    }
});


app.post('/api/v1/productosinsert', async (req, res) => {
    const { nombre, categoria, stock, precio } = req.body;

    try {
        const pool = await sql.connect(config);

        // Get the category ID based on the category name
        const categoryResult = await pool.request()
            .input('Nombre', sql.VarChar, categoria)
            .query('SELECT IDCategoria FROM Categoria WHERE Nombre = @Nombre');

        if (categoryResult.recordset.length === 0) {
            return res.status(400).send('Categoría no encontrada');
        }

        const idCategoria = categoryResult.recordset[0].IDCategoria;

        await pool.request()
            .input('Nombre', sql.VarChar, nombre)
            .input('IDCategoria', sql.Int, idCategoria)
            .input('Stock', sql.Int, stock)
            .input('Precio', sql.Decimal(18, 2), precio)
            .query('INSERT INTO Productos (Nombre, IDCategoria, Stock, Precio) VALUES (@Nombre, @IDCategoria, @Stock, @Precio)');

        res.status(201).send('Producto añadido exitosamente');
    } catch (err) {
        console.error('Error al añadir producto:', err);
        res.status(500).send('Error del servidor al añadir producto');
    }
});

app.delete('/api/v1/productos/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('ID', sql.Int, id)
            .query('DELETE FROM Productos WHERE IDProductos = @ID');

        if (result.rowsAffected[0] > 0) {
            res.status(200).send('Producto eliminado exitosamente.');
        } else {
            res.status(404).send('Producto no encontrado.');
        }
    } catch (err) {
        console.error('Error al eliminar producto:', err);
        res.status(500).send('Error del servidor al eliminar producto.');
    }
});


app.put('/api/v1/productos/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, categoria, stock, precio } = req.body;

    try {
        const pool = await sql.connect(config);

        // Get the category ID based on the category name
        const categoryResult = await pool.request()
            .input('Nombre', sql.VarChar, categoria)
            .query('SELECT IDCategoria FROM Categoria WHERE Nombre = @Nombre');

        if (categoryResult.recordset.length === 0) {
            return res.status(400).send('Categoría no encontrada');
        }

        const idCategoria = categoryResult.recordset[0].IDCategoria;

        const result = await pool.request()
            .input('ID', sql.Int, id)
            .input('Nombre', sql.VarChar, nombre)
            .input('IDCategoria', sql.Int, idCategoria)
            .input('Stock', sql.Int, stock)
            .input('Precio', sql.Decimal(18, 2), precio)
            .query('UPDATE Productos SET Nombre = @Nombre, IDCategoria = @IDCategoria, Stock = @Stock, Precio = @Precio WHERE IDProductos = @ID');

        if (result.rowsAffected[0] > 0) {
            res.status(200).send('Producto actualizado exitosamente.');
        } else {
            res.status(404).send('Producto no encontrado.');
        }
    } catch (err) {
        console.error('Error al actualizar producto:', err);
        res.status(500).send('Error del servidor al actualizar producto.');
    }
});

app.get('/api/v1/saldo', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query(`
                SELECT
                    d.saldo AS baseSaldo,
                    (SELECT ISNULL(SUM(monto), 0) FROM Transaccion WHERE tipo = 'ingreso') AS totalIngresos,
                    (SELECT ISNULL(SUM(monto), 0) FROM Transaccion WHERE tipo = 'egreso') AS totalEgresos,
                    d.saldo +
                    (SELECT ISNULL(SUM(monto), 0) FROM Transaccion WHERE tipo = 'ingreso') -
                    (SELECT ISNULL(SUM(monto), 0) FROM Transaccion WHERE tipo = 'egreso') AS saldoFinal
                FROM DineroDisponible d
                WHERE ID = 1;
            `);


        const saldo = result.recordset[0];
        saldo.totalIngresos = saldo.totalIngresos || 0;
        saldo.totalEgresos = saldo.totalEgresos || 0;
        saldo.saldoFinal = saldo.saldo + saldo.totalIngresos - saldo.totalEgresos;

        res.status(200).json(saldo);
    } catch (err) {
        console.error('Error al obtener el saldo:', err);
        res.status(500).send('Error del servidor al obtener el saldo');
    }
});



app.get('/api/v1/transacciones', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        // Obtener todas las transacciones
        const result = await pool.request().query('SELECT * FROM Transaccion');

        // Obtener el estado actual de DineroDisponible (ingresos, egresos, saldo)
        const dineroDisponible = await pool.request().query('SELECT * FROM DineroDisponible WHERE ID = 1');

        // Responder con las transacciones y el estado de DineroDisponible
        res.status(200).json({
            transacciones: result.recordset,
            dineroDisponible: dineroDisponible.recordset[0]
        });
    } catch (err) {
        console.error('Error al recuperar transacciones:', err);
        res.status(500).send('Error del servidor al recuperar transacciones');
    }
});


app.post('/api/v1/transaccionesinsert', async (req, res) => {
    const { descripcion, monto, tipo, fecha } = req.body;

    try {
        const pool = await sql.connect(config);

        // Validar si el tipo es 'ingreso' o 'egreso'
        if (!['ingreso', 'egreso'].includes(tipo)) {
            return res.status(400).send('Tipo de transacción inválido');
        }

        // Inserta la nueva transacción
        await pool.request()
            .input('Descripcion', sql.VarChar(255), descripcion)
            .input('Monto', sql.Decimal(10, 2), monto)
            .input('Tipo', sql.VarChar(10), tipo)
            .input('Fecha', sql.DateTime, fecha)
            .query('INSERT INTO Transaccion (descripcion, monto, tipo, fecha) VALUES (@Descripcion, @Monto, @Tipo, @Fecha)');

        // Actualiza los ingresos o egresos y el saldo
        if (tipo === 'ingreso') {
            await pool.request()
                .input('Monto', sql.Decimal(10, 2), monto)
                .query('UPDATE DineroDisponible SET ingresos = ingresos + @Monto, saldo = saldo + @Monto WHERE ID = 1');
        } else if (tipo === 'egreso') {
            await pool.request()
                .input('Monto', sql.Decimal(10, 2), monto)
                .query('UPDATE DineroDisponible SET egresos = egresos + @Monto, saldo = saldo - @Monto WHERE ID = 1');
        }

        res.status(201).send('Transacción añadida exitosamente');
    } catch (err) {
        console.error('Error al añadir transacción:', err);
        res.status(500).send('Error del servidor al añadir transacción');
    }
});





// Añadir esta línea para iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});

module.exports = app;
