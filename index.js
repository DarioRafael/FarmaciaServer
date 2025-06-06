require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');
const axios = require('axios');

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


//URL PADRE : https://bodega-server.vercel.app/

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
                    M.Stock,
                    M.Precio
                FROM Medicamentos M;
            `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener medicamentos:', err);
        res.status(500).send('Error del servidor al obtener medicamentos');
    }
});

app.put('/api/v1/medicamentos/:id', async (req, res) => {
    const { id } = req.params;
    const { NombreGenerico, Precio } = req.body;

    if (!NombreGenerico || Precio === undefined) {
        return res.status(400).json({ mensaje: 'Nombre y precio son requeridos' });
    }

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('ID', sql.Int, id)
            .input('NombreGenerico', sql.NVarChar, NombreGenerico)
            .input('Precio', sql.Decimal(10, 2), Precio)
            .query(`
                UPDATE Medicamentos
                SET NombreGenerico = @NombreGenerico, Precio = @Precio
                WHERE ID = @ID;
            `);

        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ mensaje: 'Medicamento no encontrado' });
        }

        res.status(200).json({ mensaje: 'Medicamento actualizado correctamente' });
    } catch (err) {
        console.error('Error al actualizar medicamento:', err);
        res.status(500).send('Error del servidor al actualizar medicamento');
    }
});

app.post('/api/v1/ventas', async (req, res) => {
    const { IDVenta, IDProducto, Stock, PrecioUnitario, PrecioSubtotal, FechaVenta } = req.body;

    // Validar que todos los campos estén presentes
    if (!IDVenta || !IDProducto || !Stock || !PrecioUnitario || !PrecioSubtotal || !FechaVenta) {
        return res.status(400).json({ mensaje: 'Todos los campos son requeridos' });
    }

    try {
        const pool = await sql.connect(config);

        await pool.request()
            .input('IDVenta', sql.Int, IDVenta)
            .input('IDProducto', sql.Int, IDProducto)
            .input('Stock', sql.Int, Stock)
            .input('PrecioUnitario', sql.Decimal(5, 2), PrecioUnitario)
            .input('PrecioSubtotal', sql.Decimal(7, 2), PrecioSubtotal)
            .input('FechaVenta', sql.Date, FechaVenta)
            .query(`
                INSERT INTO VentaMedicamentos (IDVenta, IDProducto, Stock, PrecioUnitario, PrecioSubtotal, FechaVenta)
                VALUES (@IDVenta, @IDProducto, @Stock, @PrecioUnitario, @PrecioSubtotal, @FechaVenta);
            `);

        res.status(201).json({ mensaje: 'Venta registrada correctamente' });
    } catch (err) {
        console.error('Error al registrar la venta:', err);
        res.status(500).json({ mensaje: 'Error del servidor al registrar la venta' });
    }
});

app.put('/api/v1/medicamentos/:id/stock', async (req, res) => {
    const { id } = req.params;
    const { cantidad } = req.body;

    if (cantidad === undefined) {
        return res.status(400).json({ mensaje: 'La cantidad es requerida' });
    }

    try {
        const pool = await sql.connect(config);

        // First get current stock
        const currentStock = await pool.request()
            .input('ID', sql.Int, id)
            .query('SELECT Stock FROM Medicamentos WHERE ID = @ID');

        if (currentStock.recordset.length === 0) {
            return res.status(404).json({ mensaje: 'Medicamento no encontrado' });
        }

        const newStock = currentStock.recordset[0].Stock - cantidad;

        // Update stock
        const result = await pool.request()
            .input('ID', sql.Int, id)
            .input('Stock', sql.Int, newStock)
            .query(`
                UPDATE Medicamentos
                SET Stock = @Stock
                WHERE ID = @ID;
            `);

        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ mensaje: 'Error al actualizar el stock' });
        }

        res.status(200).json({
            mensaje: 'Stock actualizado correctamente',
            nuevoStock: newStock
        });
    } catch (err) {
        console.error('Error al actualizar stock:', err);
        res.status(500).json({ mensaje: 'Error del servidor al actualizar stock' });
    }
});

app.put('/api/v1/medicamentos/:id/reabastecer', async (req, res) => {
    const { id } = req.params;
    const { cantidad } = req.body;

    if (cantidad === undefined) {
        return res.status(400).json({ mensaje: 'La cantidad es requerida' });
    }

    try {
        const pool = await sql.connect(config);

        // First get current stock
        const currentStock = await pool.request()
            .input('ID', sql.Int, id)
            .query('SELECT Stock FROM Medicamentos WHERE ID = @ID');

        if (currentStock.recordset.length === 0) {
            return res.status(404).json({ mensaje: 'Medicamento no encontrado' });
        }

        const newStock = currentStock.recordset[0].Stock + cantidad;

        // Update stock
        const result = await pool.request()
            .input('ID', sql.Int, id)
            .input('Stock', sql.Int, newStock)
            .query(`
                UPDATE Medicamentos
                SET Stock = @Stock
                WHERE ID = @ID;
            `);

        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ mensaje: 'Error al reabastecer el producto' });
        }

        res.status(200).json({
            mensaje: 'Producto reabastecido correctamente',
            nuevoStock: newStock
        });
    } catch (err) {
        console.error('Error al reabastecer producto:', err);
        res.status(500).json({ mensaje: 'Error del servidor al reabastecer producto' });
    }
});

app.get('/api/v1/saldo', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT saldo, ingresos, egresos FROM DineroFarmacia WHERE id = 1');

        if (result.recordset.length > 0) {
            res.status(200).json(result.recordset[0]);
        } else {
            res.status(404).send('Información de saldo no encontrada');
        }
    } catch (err) {
        console.error('Error al obtener saldo:', err);
        res.status(500).send('Error del servidor al obtener saldo');
    }
});

app.post('/api/v1/transacciones', async (req, res) => {
    const { descripcion, monto, tipo, fecha } = req.body;

    // Validación básica
    if (!descripcion || !monto || !tipo || !fecha) {
        return res.status(400).json({ mensaje: 'Todos los campos son requeridos' });
    }

    if (tipo.toLowerCase() !== 'ingreso' && tipo.toLowerCase() !== 'egreso') {
        return res.status(400).json({ mensaje: 'El tipo debe ser "ingreso" o "egreso"' });
    }

    try {
        const pool = await sql.connect(config);

        // Obtener el próximo ID disponible
        const maxIdResult = await pool.request()
            .query('SELECT ISNULL(MAX(id), 0) + 1 AS nextId FROM transaccionesFarmacia');
        const nextId = maxIdResult.recordset[0].nextId;

        // Insertar la transacción
        await pool.request()
            .input('id', sql.Int, nextId)
            .input('descripcion', sql.VarChar(255), descripcion)
            .input('monto', sql.Decimal(10, 2), monto)
            .input('tipo', sql.VarChar(50), tipo)
            .input('fecha', sql.Date, new Date(fecha))
            .query(`
                INSERT INTO transaccionesFarmacia (id, descripcion, monto, tipo, fecha)
                VALUES (@id, @descripcion, @monto, @tipo, @fecha);
            `);

        res.status(201).json({
            mensaje: 'Transacción registrada correctamente',
            id: nextId
        });
    } catch (err) {
        console.error('Error al registrar la transacción:', err);
        res.status(500).json({ mensaje: 'Error del servidor al registrar la transacción' });
    }
});


app.get('/api/v1/transaccionesGet', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        // Query to get all transactions
        const result = await pool.request()
            .query('SELECT id, descripcion, monto, tipo, fecha FROM transaccionesFarmacia ORDER BY fecha DESC');

        res.status(200).json({
            transacciones: result.recordset
        });
    } catch (err) {
        console.error('Error al obtener transacciones:', err);
        res.status(500).json({ mensaje: 'Error del servidor al obtener las transacciones' });
    }
});


// Endpoint GET para obtener todos los pedidos
app.get('/api/v1/pedidosGet', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        const pedidosResult = await pool.request().query(`
            SELECT * FROM pedidos;
        `);
        const pedidos = pedidosResult.recordset;

        const productosResult = await pool.request().query(`
            SELECT * FROM productos_pedido;
        `);
        const productos = productosResult.recordset;

        const pedidosConProductos = pedidos.map(pedido => {
            const productosDelPedido = productos.filter(p => p.pedido_id === pedido.id);
            return {
                ...pedido,
                productos: productosDelPedido
            };
        });

        res.status(200).json({ pedidos: pedidosConProductos });

    } catch (error) {
        console.error('Error al obtener pedidos:', error);
        res.status(500).json({ message: 'Error al obtener los pedidos', error: error.message });
    }
});


// Endpoint PUT para actualizar el estado de un pedido
app.put('/api/v1/pedidos/:id', async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    if (!estado) {
        return res.status(400).json({ message: 'El estado es obligatorio' });
    }

    try {
        const pool = await sql.connect(config);

        // Actualizar el estado del pedido
        const result = await pool.request()
            .input('id', sql.Int, id)
            .input('estado', sql.NVarChar(20), estado)
            .query(`
                UPDATE pedidos 
                SET estado = @estado, fecha_actualizacion = GETDATE() 
                WHERE id = @id;
                
                SELECT * FROM pedidos WHERE id = @id;
            `);

        if (result.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        res.status(200).json({
            message: 'Estado del pedido actualizado',
            pedido: result.recordset[0]
        });
    } catch (error) {
        console.error('Error al actualizar el pedido:', error);
        res.status(500).json({ message: 'Error al actualizar el pedido', error: error.message });
    }
});


// POST para crear un nuevo pedido con sus productos
app.post('/api/v1/pedidos', async (req, res) => {
    const { codigo_pedido, proveedor, estado, total, notas, productos } = req.body;

    if (!codigo_pedido || !proveedor || !estado || !total || !productos || !Array.isArray(productos)) {
        return res.status(400).json({ message: 'Campos obligatorios faltantes o productos inválidos' });
    }

    try {
        const pool = await sql.connect(config);

        // Inicia una transacción
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);
            request.input('codigo_pedido', sql.NVarChar(50), codigo_pedido);
            request.input('proveedor', sql.NVarChar(100), proveedor);
            request.input('estado', sql.NVarChar(20), estado);
            request.input('total', sql.Decimal(10, 2), total);
            request.input('notas', sql.NVarChar(sql.MAX), notas || '');

            // Insertar el pedido
            const result = await request.query(`
                INSERT INTO pedidos (codigo_pedido, proveedor, fecha_creacion, fecha_actualizacion, estado, total, notas)
                VALUES (@codigo_pedido, @proveedor, GETDATE(), GETDATE(), @estado, @total, @notas);
                SELECT SCOPE_IDENTITY() AS id;
            `);

            const pedidoId = result.recordset[0].id;

            // Insertar cada producto
            for (const producto of productos) {
                const prodRequest = new sql.Request(transaction);
                prodRequest.input('pedido_id', sql.Int, pedidoId);
                prodRequest.input('nombre', sql.NVarChar(100), producto.nombre);
                prodRequest.input('precio', sql.Decimal(10, 2), producto.precio);
                prodRequest.input('cantidad', sql.Int, producto.cantidad);

                await prodRequest.query(`
                    INSERT INTO productos_pedido (pedido_id, nombre, precio, cantidad)
                    VALUES (@pedido_id, @nombre, @precio, @cantidad);
                `);
            }

            await transaction.commit();

            res.status(201).json({
                message: 'Pedido y productos creados exitosamente',
                pedido: { id: pedidoId, codigo_pedido, proveedor, estado, total, notas, productos }
            });
        } catch (err) {
            await transaction.rollback();
            console.error('Error al crear el pedido:', err);
            res.status(500).json({ message: 'Error al crear el pedido', error: err.message });
        }

    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({ message: 'Error de conexión a la base de datos', error: err.message });
    }
});

app.post('/api/v1/bodega/pagar-pedido', async (req, res) => {
    const { pedido_id } = req.body;

    if (!pedido_id) {
        return res.status(400).json({
            message: 'Se requiere el ID del pedido'
        });
    }

    try {
        const pool = await sql.connect(config);

        const pedidoResult = await pool.request()
            .input('id', sql.Int, pedido_id)
            .query('SELECT * FROM pedidos WHERE id = @id');

        if (pedidoResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const pedido = pedidoResult.recordset[0];

        if (pedido.estado === 'cancelado') {
            return res.status(400).json({ message: 'No se puede pagar un pedido que ha sido cancelado' });
        }

        if (pedido.estado === 'completado') {
            return res.status(400).json({ message: 'No se puede pagar un pedido que ya fue completado' });
        }

        if (pedido.estado === 'pagado') {
            return res.status(400).json({ message: 'Este pedido ya está pagado' });
        }

        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);

            await request
                .input('id', sql.Int, pedido_id)
                .input('estado', sql.NVarChar(20), 'pagado')
                .input('nota', sql.NVarChar(sql.MAX), 'Pedido marcado como pagado')
                .query(`
                    UPDATE pedidos 
                    SET estado = @estado, 
                        fecha_actualizacion = GETDATE(),
                        notas = CASE 
                                  WHEN notas IS NULL OR notas = '' THEN @nota
                                  ELSE notas + '; ' + @nota
                                END
                    WHERE id = @id
                `);

            await transaction.commit();

            res.status(200).json({
                message: 'Pedido marcado como pagado exitosamente',
                pedido_id,
                estado: 'pagado'
            });
        } catch (err) {
            await transaction.rollback();
            console.error('Error al marcar el pedido como pagado:', err);
            res.status(500).json({
                message: 'Error al marcar el pedido como pagado',
                error: err.message
            });
        }
    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: err.message
        });
    }
});

app.post('/api/v1/bodega/completar-pedido', async (req, res) => {
    const { pedido_id } = req.body;

    if (!pedido_id) {
        return res.status(400).json({
            message: 'Se requiere el ID del pedido'
        });
    }

    try {
        const pool = await sql.connect(config);

        const pedidoResult = await pool.request()
            .input('id', sql.Int, pedido_id)
            .query('SELECT * FROM pedidos WHERE id = @id');

        if (pedidoResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const pedido = pedidoResult.recordset[0];

        if (pedido.estado === 'cancelado') {
            return res.status(400).json({ message: 'No se puede completar un pedido que ha sido cancelado' });
        }

        if (pedido.estado === 'completado') {
            return res.status(400).json({ message: 'Este pedido ya está completado' });
        }

        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);

            await request
                .input('id', sql.Int, pedido_id)
                .input('estado', sql.NVarChar(20), 'completado')
                .input('nota', sql.NVarChar(sql.MAX), 'Pedido marcado como completado')
                .query(`
                    UPDATE pedidos 
                    SET estado = @estado, 
                        fecha_actualizacion = GETDATE(),
                        notas = CASE 
                                  WHEN notas IS NULL OR notas = '' THEN @nota
                                  ELSE notas + '; ' + @nota
                                END
                    WHERE id = @id
                `);

            await transaction.commit();

            res.status(200).json({
                message: 'Pedido marcado como completado exitosamente',
                pedido_id,
                estado: 'completado'
            });
        } catch (err) {
            await transaction.rollback();
            console.error('Error al marcar el pedido como completado:', err);
            res.status(500).json({
                message: 'Error al marcar el pedido como completado',
                error: err.message
            });
        }
    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: err.message
        });
    }
});

app.get('/api/v1/inventarioConCodigo', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query(`
                SELECT
                    M.ID,
                    M.Codigo,
                    M.NombreGenerico,
                    M.NombreMedico,
                    M.Fabricante,
                    M.Contenido,
                    M.FormaFarmaceutica,
                    FORMAT(M.FechaFabricacion, 'yyyy-MM-dd') AS FechaFabricacion,
                    M.Presentacion,
                    FORMAT(M.FechaCaducidad, 'yyyy-MM-dd') AS FechaCaducidad,
                    M.UnidadesPorCaja,
                    M.Stock,
                    M.Precio
                FROM Medicamentos M;
            `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener medicamentos:', err);
        res.status(500).send('Error del servidor al obtener medicamentos');
    }
});




app.get('/api/v1/medicamentos-farmacia-manuelito', async (req, res) => {
    try {
        const response = await axios.get('https://ladybird-regular-blatantly.ngrok-free.app/api/producto/inventario');

        const productos = response.data;

        res.status(200).json(productos);
    } catch (err) {
        console.error('Error al obtener inventario externo:', err.message);
        res.status(500).json({
            mensaje: 'Error al obtener el inventario externo',
            error: err.message
        });
    }//Pruebita
});

app.get('/api/v1/medicamentos-farmacia-gaelle', async (req, res) => {
    try {
        const response = await axios.get('https://farmacia-api.loca.lt/api/medicamentos');

        const medicamentos = response.data;

        res.status(200).json(medicamentos);
    } catch (err) {
        console.error('Error al obtener medicamentos de Farmacia API:', err.message);
        res.status(500).json({
            mensaje: 'Error al obtener los medicamentos de Farmacia API',
            error: err.message
        });
    }
});

app.get('/api/v1/medicamentos-farmacia-dele', async (req, res) => {
    try {
        const response = await axios.get('https://farmacia-dele.loca.lt/api/medicamentos');

        const medicamentos = response.data;

        res.status(200).json(medicamentos);
    } catch (err) {
        console.error('Error al obtener medicamentos de Farmacia Dele:', err.message);
        res.status(500).json({
            mensaje: 'Error al obtener los medicamentos de Farmacia Dele',
            error: err.message
        });
    }
});


app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});

module.exports = app;
