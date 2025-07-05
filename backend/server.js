// backend/server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Para permitir solicitudes desde el frontend
const fs = require('fs'); // Para leer/escribir archivos (base de datos simple)
const path = require('path'); // Para manejar rutas de archivos
const bcrypt = require('bcrypt'); // Para hashear contraseñas de forma segura

const app = express();
const PORT = 3000; // Puerto donde se ejecutará el backend

// Middleware
app.use(bodyParser.json()); // Para parsear cuerpos de solicitud JSON
app.use(cors()); // Permite que tu frontend (en GitHub Pages) haga solicitudes a este backend

// Ruta al archivo de "base de datos" de usuarios
const USERS_DB_PATH = path.join(__dirname, 'users.json');

// Función para leer los usuarios de la "base de datos"
function readUsers() {
    try {
        const data = fs.readFileSync(USERS_DB_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // Si el archivo no existe o está vacío, devuelve un array vacío
        if (error.code === 'ENOENT' || data === '') {
            return [];
        }
        console.error('Error al leer el archivo de usuarios:', error);
        return [];
    }
}

// Función para guardar usuarios en la "base de datos"
function saveUsers(users) {
    try {
        fs.writeFileSync(USERS_DB_PATH, JSON.stringify(users, null, 2), 'utf8');
    } catch (error) {
        console.error('Error al guardar el archivo de usuarios:', error);
    }
}

// Endpoint para el registro de usuarios
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Correo electrónico y contraseña son requeridos.' });
    }

    let users = readUsers();

    // Verificar si el usuario ya existe
    if (users.find(user => user.email === email)) {
        return res.status(409).json({ message: 'El usuario con este correo electrónico ya existe.' });
    }

    try {
        // Hashear la contraseña antes de guardarla
        const hashedPassword = await bcrypt.hash(password, 10); // 10 es el costo de salting

        const newUser = { email, password: hashedPassword };
        users.push(newUser);
        saveUsers(users);

        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor al registrar usuario.' });
    }
});

// Endpoint para el inicio de sesión de usuarios
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Correo electrónico y contraseña son requeridos.' });
    }

    const users = readUsers();

    // Buscar el usuario por correo electrónico
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    try {
        // Comparar la contraseña proporcionada con la contraseña hasheada almacenada
        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            // En un entorno real, aquí generarías un token JWT (JSON Web Token)
            // y lo enviarías al frontend para gestionar la sesión.
            res.status(200).json({ message: 'Inicio de sesión exitoso.', user: { email: user.email } });
        } else {
            res.status(401).json({ message: 'Credenciales inválidas.' });
        }
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({ message: 'Error interno del servidor al iniciar sesión.' });
    }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor backend de Insabarrio ejecutándose en http://localhost:${PORT}`);
    console.log('¡Recuerda que este es un ejemplo simple! Para producción, usa una base de datos real y JWT para sesiones.');
});
