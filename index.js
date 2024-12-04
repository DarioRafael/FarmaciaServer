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
            .input('correo', sql.VarChar, email)  // Manteniendo el tipo como sql.VarChar
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

        // Verificar si el correo ya está registrado utilizando el procedimiento almacenado
        const result = await pool.request()
            .input('correo', sql.VarChar, correo)
            .execute('sp_VerificarCorreo');  // Llamamos al procedimiento almacenado

        if (result.recordset[0].CorreoExistente === 1) {
            return res.status(400).send('El correo ya está registrado.');
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Llamar al procedimiento almacenado para insertar el nuevo trabajador
        await pool.request()
            .input('nombre', sql.VarChar, nombre)
            .input('correo', sql.VarChar, correo)
            .input('contraseña', sql.VarChar, hashedPassword)
            .input('rol', sql.VarChar, rol)
            .input('fecha_creacion', sql.DateTime, new Date())
            .input('estado', sql.VarChar, 'activo')
            .execute('sp_RegistrarTrabajador');  // Llamar al procedimiento almacenado para insertar el trabajador

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
            .query('INSERT INTO Transaccion (descripcion, monto, tipo, fecha) VALUES (@Descripcion, @Monto, @Tipo, @Fecha)');

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
    const transaction = new sql.Transaction(pool);

    try {
        await transaction.begin();

        const ventaResult = await new sql.Request(transaction)
            .input('FechaVenta', sql.DateTime, new Date())
            .query(`
                INSERT INTO Ventas (FechaVenta)
                OUTPUT INSERTED.IDVenta
                VALUES (@FechaVenta)
            `);

        const idVenta = ventaResult.recordset[0].IDVenta;

        for (const producto of productos) {
            const { IDProducto, Stock, PrecioUnitario, PrecioSubtotal } = producto;

            const stockResult = await new sql.Request(transaction)
                .input('IDProducto', sql.Int, IDProducto)
                .query('SELECT Stock FROM Productos WHERE IDProductos = @IDProducto');

            if (stockResult.recordset.length === 0) {
                throw new Error(`Producto con ID ${IDProducto} no encontrado`);
            }

            const stockDisponible = stockResult.recordset[0].Stock;
            if (stockDisponible < Stock) {
                throw new Error(`Stock insuficiente para el producto ${IDProducto}`);
            }

            await new sql.Request(transaction)
                .input('IDVenta', sql.Int, idVenta) // Asociar el producto con la venta principal
                .input('IDProducto', sql.Int, IDProducto)
                .input('Stock', sql.Int, Stock)
                .input('PrecioUnitario', sql.Decimal(10, 2), PrecioUnitario)
                .input('PrecioSubtotal', sql.Decimal(10, 2), PrecioSubtotal)
                .query(`
                    INSERT INTO VentasProductos (IDVenta, IDProducto, Stock, PrecioUnitario, PrecioSubtotal)
                    VALUES (@IDVenta, @IDProducto, @Stock, @PrecioUnitario, @PrecioSubtotal)
                `);

            await new sql.Request(transaction)
                .input('IDProducto', sql.Int, IDProducto)
                .input('CantidadVendida', sql.Int, Stock)
                .query(`
                    UPDATE Productos
                    SET Stock = Stock - @CantidadVendida
                    WHERE IDProductos = @IDProducto
                `);
        }

        await transaction.commit();
        res.status(201).json({
            message: 'Venta registrada exitosamente',
            idVenta: idVenta,
        });

    } catch (error) {
        await transaction.rollback();
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
