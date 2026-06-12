# Synapto 🎯

Plataforma de quizzes en tiempo real — estilo Kahoot. Los jugadores se unen desde el celular escaneando un QR, responden preguntas en vivo y ven el ranking al instante.

## Estructura del proyecto

```
synapto/
├── backend/          → Node.js + Express + Socket.io (deploy en Railway)
│   ├── server.js
│   ├── db.js
│   └── package.json
└── frontend/         → HTML/CSS/JS estático (deploy en Vercel)
    ├── index.html    → Landing page
    ├── admin/        → Panel de administración
    ├── player/       → Vista para jugadores (mobile)
    ├── screen/       → Pantalla de proyección
    └── vercel.json
```

## Configuración local

### 1. Clonar y preparar

```bash
git clone https://github.com/TU_USUARIO/synapto.git
cd synapto
```

### 2. Backend

```bash
cd backend
npm install
npm run dev   # corre en http://localhost:4000
```

### 3. Frontend

Abrí `frontend/index.html` directamente en el navegador, o usá un servidor estático:

```bash
cd frontend
npx serve . -p 3000
```

---

## Deploy en producción

### Backend → Railway

1. Entrá a [railway.app](https://railway.app) y creá un nuevo proyecto
2. Conectá tu repo de GitHub y seleccioná la carpeta `backend`
3. Railway detecta automáticamente Node.js y hace el deploy
4. Copiá la URL pública que te da Railway (ej: `https://synapto-backend.up.railway.app`)

### Frontend → Vercel

1. Entrá a [vercel.com](https://vercel.com) y creá un nuevo proyecto
2. Conectá tu repo de GitHub y seleccioná la carpeta `frontend` como root
3. En **Settings → Environment Variables** agregá:
   ```
   SYNAPTO_BACKEND_URL = https://TU-BACKEND.up.railway.app
   ```
4. Vercel hace el deploy automático en cada push

### Conectar frontend con backend

En el archivo `frontend/config.js` ya está la configuración. En Vercel, la variable `SYNAPTO_BACKEND_URL` se inyecta automáticamente.

Para que funcione en HTML estático, agregá en el `<head>` de cada página antes del script:

```html
<script>
  window.SYNAPTO_BACKEND_URL = 'https://TU-BACKEND.up.railway.app';
</script>
```

O bien en Vercel podés usar un `_headers` o un edge function para inyectarlo.

---

## Variables de entorno

### Backend (Railway)

| Variable | Descripción | Default |
|----------|-------------|---------|
| `PORT` | Puerto del servidor | `4000` |
| `FRONTEND_URL` | URL del frontend (para QR) | `http://localhost:3000` |
| `DB_PATH` | Ruta de la base de datos | `./synapto.db` |

---

## Cómo funciona

1. **Admin** crea un quiz con preguntas y respuestas múltiples
2. **Admin** inicia una partida → se genera un código y QR únicos
3. **Jugadores** escanean el QR o ingresan el código en `synapto.vercel.app/player`
4. **Pantalla** se abre en el proyector con `synapto.vercel.app/screen?code=ABC123`
5. **Admin** avanza las preguntas desde su panel
6. Todos ven las preguntas en tiempo real, responden desde el celular
7. Al finalizar, se muestra el ranking final

## Puntuación

- Respuesta correcta: **500 puntos** base
- Bonus por velocidad: hasta **500 puntos** adicionales (proporcional al tiempo restante)
- Respuesta incorrecta o sin respuesta: **0 puntos**

---

## Claude Code — Trabajar con IA

Para que Claude pueda editar este proyecto directamente desde tu terminal:

```bash
npm install -g @anthropic/claude-code
cd synapto
claude
```

Desde ahí podés pedirle cambios directamente. Ejemplo:
- *"Agregá una pantalla de espera entre preguntas"*
- *"Cambiá el límite de tiempo por defecto a 30 segundos"*
- *"Agregá soporte para imágenes en las preguntas"*

---

## Stack

- **Backend**: Node.js, Express, Socket.io, better-sqlite3
- **Frontend**: HTML/CSS/JS puro (sin frameworks)
- **Deploy backend**: Railway
- **Deploy frontend**: Vercel
- **Tiempo real**: WebSockets (Socket.io)
- **QR**: librería `qrcode`
