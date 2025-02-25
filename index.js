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
    'https://farmacia-app-two.vercel.app',  // <-- Sin la barra final
    /^http:\/\/localhost:\d+$/
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
            .execute('sp_AutenticarTrabajador');

        if (result.recordset.length > 0) {
            const user = result.recordset[0];

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
                        rol: user.rol,
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
        const userRole = req.user.rol;

        if (roles.includes(userRole)) {
            return next();
        } else {
            return res.status(403).send('No tienes permisos para acceder a esta ruta.');
        }
    };
};

app.get('/api/v1/admin', authorizeRole(['admin']), (req, res) => {
    res.status(200).send('Acceso a administrador concedido.');
});



app.post('/api/v1/registrar', async (req, res) => {
    const { nombre, correo, password, rol } = req.body;

    if (!nombre || !correo || !password || !rol) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        const pool = await sql.connect(config);

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.request()
            .input('nombre', sql.VarChar, nombre)
            .input('correo', sql.VarChar, correo)
            .input('contraseña', sql.VarChar, hashedPassword)
            .input('rol', sql.VarChar, rol)
            .input('fecha_creacion', sql.DateTime, new Date())
            .input('estado', sql.VarChar, 'activo')
            .execute('sp_RegistrarTrabajadorTransaccional');

        res.status(201).send('Usuario registrado correctamente.');
    } catch (err) {
        if (err.message.includes('El correo ya está registrado')) {
            res.status(400).send('El correo ya está registrado.');
        } else {
            console.error('Error al registrar usuario:', err.message);
            res.status(500).send('Error al registrar usuario.');
        }
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

app.patch('/api/v1/trabajadores/:id/estado', async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    if (!estado || !['activo', 'inactivo'].includes(estado.toLowerCase())) {
        return res.status(400).send("Estado inválido. Debe ser 'activo' o 'inactivo'.");
    }

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('id', sql.Int, id)
            .input('estado', sql.VarChar, estado.toLowerCase())
            .execute('sp_ActualizarEstadoTrabajador');

        res.status(200).json({ message: `Estado del trabajador actualizado a '${estado}'.` });
    } catch (err) {
        if (err.message.includes('Trabajador no encontrado')) {
            res.status(404).send('Trabajador no encontrado.');
        } else {
            console.error('Error al actualizar estado del trabajador:', err);
            res.status(500).send('Error del servidor al actualizar estado del trabajador.');
        }
    }
});

app.get('/api/v1/keepalive', (req, res) => {
    res.status(200).send('Server is alive!');
});

app.post('/api/v1/actualizar-contrasenas', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        const request = pool.request();
        const result = await request.query('SELECT id, contraseña FROM Trabajadores');

        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        for (const user of result.recordset) {
            if (user.contraseña) {
                const hashedPassword = await bcrypt.hash(user.contraseña, 10);

                const transactionRequest = new sql.Request(transaction);

                await transactionRequest
                    .input('id', sql.Int, user.id)
                    .input('contraseña', sql.VarChar, hashedPassword)
                    .query('UPDATE Trabajadores SET contraseña = @contraseña WHERE id = @id');
            }
        }

        await transaction.commit();

        res.status(200).send('Contraseñas actualizadas correctamente.');
    } catch (err) {
        console.error('Error al actualizar contraseñas:', err.message);

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
            .execute('sp_ObtenerCategorias');

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener categorias:', err);
        res.status(500).send('Error del servidor al obtener categorias');
    }
});


//FIRST
app.get('/api/v1/medicamentos', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query(`
                SELECT 
                    M.ID,
                    M.NombreGenerico,
                    M.NombreMedico,
                    M.Fabricante,
                    M.Contenido,
                    M.FormaFarmaceutica,
                    M.FechaFabricacion,
                    M.Presentacion,
                    M.FechaCaducidad,
                    M.UnidadesPorCaja,
                    M.Precio
                FROM Medicamentos M;
            `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener medicamentos:', err);
        res.status(500).send('Error del servidor al obtener medicamentos');
    }
});


app.post('/api/v1/productosinsert', async (req, res) => {
    const { nombre, categoria, stock, precio } = req.body;

    try {
        const pool = await sql.connect(config);

        // Llamar al procedimiento almacenado con el prefijo 'sp'
        const result = await pool.request()
            .input('Nombre', sql.VarChar, nombre)
            .input('Categoria', sql.VarChar, categoria)
            .input('Stock', sql.Int, stock)
            .input('Precio', sql.Decimal(18, 2), precio)
            .execute('sp_InsertarProducto');

        res.status(201).send('Producto añadido exitosamente');
    } catch (err) {
        if (err.message.includes('Categoría no encontrada')) {
            return res.status(400).send('Categoría no encontrada');
        }
        console.error('Error al añadir producto:', err);
        res.status(500).send('Error del servidor al añadir producto');
    }
});


app.delete('/api/v1/productos/:id', async (req, res) => {
    const { id } = req.params;

    try {
        console.log(`Attempting to delete product with ID: ${id}`); // Add logging

        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('ID', sql.Int, parseInt(id)) // Ensure ID is parsed as integer
            .query('DELETE FROM Productos WHERE IDProductos = @ID');

        console.log(`Delete result: ${result.rowsAffected[0]}`); // Log rows affected

        if (result.rowsAffected[0] > 0) {
            res.status(200).send('Producto eliminado exitosamente.');
        } else {
            res.status(404).send('Producto no encontrado.');
        }
    } catch (err) {
        console.error('Detailed error al eliminar producto:', err);
        res.status(500).send(`Error del servidor al eliminar producto: ${err.message}`);
    }
});


app.put('/api/v1/productos/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, categoria, stock, precio } = req.body;

    try {
        const pool = await sql.connect(config);

        // Llamar al procedimiento almacenado con el prefijo 'sp'
        const result = await pool.request()
            .input('ID', sql.Int, id)
            .input('Nombre', sql.VarChar, nombre)
            .input('Categoria', sql.VarChar, categoria)
            .input('Stock', sql.Int, stock)
            .input('Precio', sql.Decimal(18, 2), precio)
            .execute('sp_ActualizarProducto');  // Llamada al procedimiento almacenado con prefijo 'sp'

        res.status(200).send('Producto actualizado exitosamente.');
    } catch (err) {
        if (err.message.includes('Categoría no encontrada')) {
            return res.status(400).send('Categoría no encontrada');
        }
        if (err.message.includes('Producto no encontrado')) {
            return res.status(404).send('Producto no encontrado');
        }
        console.error('Error al actualizar producto:', err);
        res.status(500).send('Error del servidor al actualizar producto.');
    }
});


app.get('/api/v1/saldo', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT * FROM dbo.fn_CalcularSaldo()');

        const saldo = result.recordset[0];
        res.status(200).json(saldo);
    } catch (err) {
        console.error('Error al obtener el saldo:', err);
        res.status(500).send('Error del servidor al obtener el saldo');
    }
});



app.get('/api/v1/transacciones', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        const result = await pool.request().query('SELECT * FROM Transaccion');



        res.status(200).json({
            transacciones: result.recordset,
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

        if (!['ingreso', 'egreso'].includes(tipo)) {
            return res.status(400).send('Tipo de transacción inválido');
        }

        await pool.request()
            .input('Descripcion', sql.VarChar(255), descripcion)
            .input('Monto', sql.Decimal(10, 2), monto)
            .input('Tipo', sql.VarChar(10), tipo)
            .input('Fecha', sql.DateTime, fecha)
            .execute('sp_InsertarTransaccion');

        res.status(201).send('Transacción añadida exitosamente');
    } catch (err) {
        console.error('Error al añadir transacción:', err);
        res.status(500).send('Error del servidor al añadir transacción');
    }
});

app.get('/api/v1/ventas', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        const result = await pool.request().query(`
            SELECT
                v.IDVenta,
                IDCategoria = (SELECT c.IDCategoria FROM Productos c  WHERE c.IDProductos = v.IDProducto),
                v.IDProducto,
                Producto = (SELECT p.Nombre FROM Productos p WHERE p.IDProductos = v.IDProducto),
                v.Stock,
                v.PrecioUnitario,
                v.PrecioSubtotal,
                Fecha =(SELECT ven.FechaVenta FROM Ventas ven WHERE ven.IDVenta = v.IDVenta)
            FROM VentasProductos v
        `);

        res.status(200).json({
            ventas: result.recordset,
        });
    } catch (err) {
        console.error('Error al recuperar ventas:', err);
        res.status(500).send('Error del servidor al recuperar ventas');
    }
});

app.post('/api/v1/ventas', async (req, res) => {
    const { productos } = req.body;

    if (!Array.isArray(productos) || productos.length === 0) {
        return res.status(400).json({
            message: 'Debe proporcionar al menos un producto para la venta',
        });
    }

    const pool = await sql.connect(config);

    try {
        const table = new sql.Table('TVP_Productos');
        table.columns.add('IDProducto', sql.Int);
        table.columns.add('Stock', sql.Int);
        table.columns.add('PrecioUnitario', sql.Decimal(10, 2));
        table.columns.add('PrecioSubtotal', sql.Decimal(10, 2));

        productos.forEach(producto => {
            table.rows.add(producto.IDProducto, producto.Stock, producto.PrecioUnitario, producto.PrecioSubtotal);
        });

        const result = await pool.request()
            .input('FechaVenta', sql.DateTime, new Date())
            .input('Productos', table)
            .execute('sp_InsertarVenta');

        const idVenta = result.returnValue;

        res.status(201).json({
            message: 'Venta registrada exitosamente',
            idVenta: idVenta,
        });

    } catch (error) {
        console.error('Error al procesar la venta:', error);
        res.status(500).json({
            message: 'Error al procesar la venta',
            error: error.message,
        });
    }
});

app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});

module.exports = app;
