require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { router: apiRoutes, setSocketIo, sessions } = require('./routes');
const { User, ScheduledMessage, Message } = require('./models');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

setSocketIo(io);

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3000;

mongoose.connect(MONGO_URI)
  .then(() => console.log('Conectado ao MongoDB Atlas'))
  .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

app.use('/api', apiRoutes);

app.get('/', (req, res) => {
  res.send('Servidor da plataforma de mensagens está no ar!');
});

io.on('connection', (socket) => {
  console.log('Um usuário conectou via WebSocket:', socket.id);
  
  socket.on('join_room', (userId) => {
    socket.join(userId);
    console.log(`Socket ${socket.id} entrou na sala do usuário ${userId}`);
  });

  socket.on('disconnect', () => {
    console.log('Usuário desconectado:', socket.id);
  });
});

setInterval(async () => {
    const now = new Date();
    const messagesToSend = await ScheduledMessage.find({
        sendAt: { $lte: now },
        status: 'Pendente'
    });

    for (const msg of messagesToSend) {
        const user = await User.findById(msg.userId);
        const socket = sessions.get(msg.userId.toString());
        
        if (user && user.whatsappConnected && socket) {
            try {
                const jid = `${msg.to}@s.whatsapp.net`;
                await socket.sendMessage(jid, { text: msg.body });
                await new Message({ userId: msg.userId, to: msg.to, body: msg.body, status: 'Enviada' }).save();
                msg.status = 'Enviada';
                await msg.save();
            } catch (e) {
                console.log(`Falha ao enviar mensagem agendada ${msg._id}:`, e.message);
            }
        }
    }
}, 60000); // Roda a cada 60 segundos


server.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});