const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { Readable } = require('stream');
const xlsx = require('xlsx');
const { default: makeWASocket, DisconnectReason, useMultiFileAuthState } = require('@whiskeysockets/baileys');
const pino = require('pino');
const { User, Payment, Message, ScheduledMessage } = require('./models');
const mongoose = require('mongoose');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 } });

const sessions = new Map();
let io = null;

const setSocketIo = (socketIoInstance) => {
    io = socketIoInstance;
};

const PLAN_LIMITS = {
    Free: { msgDay: 50, media: false, video: false, reports: false, chat: false },
    Padrão: { msgDay: 1200, media: true, video: false, reports: true, chat: false },
    Premium: { msgDay: 5000, media: true, video: true, reports: true, chat: true },
};

async function startBaileysSession(userId) {
    if (sessions.has(userId)) return sessions.get(userId);

    const { state, saveCreds } = await useMultiFileAuthState(`auth_info_${userId}`);
    const socket = makeWASocket({
        logger: pino({ level: 'silent' }),
        printQRInTerminal: false,
        auth: state,
    });

    socket.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, qr } = update;
        if (qr && io) {
            io.to(userId).emit('qr_code', qr);
        }
        if (connection === 'close') {
            const shouldReconnect = (lastDisconnect?.error)?.output?.statusCode !== DisconnectReason.loggedOut;
            if (shouldReconnect) {
                await startBaileysSession(userId);
            } else {
                sessions.delete(userId);
                await User.findByIdAndUpdate(userId, { whatsappConnected: false });
                if (io) io.to(userId).emit('whatsapp_disconnected');
            }
        } else if (connection === 'open') {
            await User.findByIdAndUpdate(userId, { whatsappConnected: true });
            if (io) io.to(userId).emit('whatsapp_connected');
        }
    });

    socket.ev.on('creds.update', saveCreds);
    
    socket.ev.on('messages.upsert', async (m) => {
        const msg = m.messages[0];
        if (!msg.key.fromMe && m.type === 'notify' && io) {
             io.to(userId).emit('new_message', msg);
        }
    });

    sessions.set(userId, socket);
    return socket;
}

const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token não fornecido' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.userId = decoded.id;
        next();
    });
};

const adminMiddleware = async (req, res, next) => {
    const user = await User.findById(req.userId);
    if (!user || !user.isAdmin) {
        return res.status(403).json({ message: 'Acesso negado.' });
    }
    next();
};

const planCheckMiddleware = (features = {}) => async (req, res, next) => {
    const user = await User.findById(req.userId);
    const userPlan = PLAN_LIMITS[user.plan];

    if (features.minPlan) {
        const plans = Object.keys(PLAN_LIMITS);
        if (plans.indexOf(user.plan) < plans.indexOf(features.minPlan)) {
            return res.status(403).json({ message: `Funcionalidade disponível apenas a partir do plano ${features.minPlan}.` });
        }
    }
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const messagesSentToday = await Message.countDocuments({ userId: req.userId, createdAt: { $gte: today } });
    
    if(messagesSentToday >= userPlan.msgDay) {
        return res.status(403).json({ message: 'Limite diário de mensagens atingido.' });
    }

    req.user = user;
    req.userPlan = userPlan;
    req.messagesSentToday = messagesSentToday;
    next();
};

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length !== 4 || !/^\d{4}$/.test(password)) {
    return res.status(400).json({ message: 'Username é obrigatório e a senha deve ter 4 dígitos numéricos.' });
  }
  try {
    const newUser = new User({ username, password });
    await newUser.save();
    res.status(201).json({ message: 'Usuário criado com sucesso!' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao criar usuário', error: error.message });
  }
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const adminUser = await User.findOneAndUpdate({ username: ADMIN_USERNAME, isAdmin: true }, { username: ADMIN_USERNAME, password: ADMIN_PASSWORD, isAdmin: true, plan: 'Premium' }, { upsert: true, new: true });
        const token = jwt.sign({ id: adminUser.id, isAdmin: true }, JWT_SECRET, { expiresIn: '8h' });
        return res.json({ token, isAdmin: true });
    }
    const user = await User.findOne({ username, password });
    if (!user) return res.status(401).json({ message: 'Credenciais inválidas' });
    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, isAdmin: user.isAdmin });
});

router.get('/me', authMiddleware, async (req, res) => {
    const user = await User.findById(req.userId).select('-password');
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const messagesSentToday = await Message.countDocuments({ userId: req.userId, createdAt: { $gte: today } });
    const planLimits = PLAN_LIMITS[user.plan];
    res.json({ user, planLimits, messagesSentToday });
});

router.get('/whatsapp/connect', authMiddleware, async (req, res) => {
    try {
        if(io && req.query.socketId) {
             const socket = io.sockets.sockets.get(req.query.socketId);
             if(socket) socket.join(req.userId);
        }
        await startBaileysSession(req.userId);
        res.status(200).json({ message: 'Iniciando conexão. Aguarde o QR Code.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao conectar ao WhatsApp.', error: error.message });
    }
});

router.get('/whatsapp/status', authMiddleware, async (req, res) => {
    const user = await User.findById(req.userId);
    res.json({ connected: user.whatsappConnected });
});

router.get('/whatsapp/disconnect', authMiddleware, async (req, res) => {
    try {
        const socket = sessions.get(req.userId);
        if (socket) {
            await socket.logout();
            sessions.delete(req.userId);
        }
        await User.findByIdAndUpdate(req.userId, { whatsappConnected: false });
        res.status(200).json({ message: 'Desconectado com sucesso.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao desconectar.' });
    }
});

router.post('/whatsapp/send', authMiddleware, planCheckMiddleware({ minPlan: 'Free' }), upload.single('media'), async (req, res) => {
    const { to, message } = req.body;
    const { user, userPlan } = req;
    const socket = sessions.get(req.userId);

    if (!socket || !user.whatsappConnected) return res.status(400).json({ message: 'WhatsApp não está conectado.' });
    
    let mediaUrl = '';
    let mediaOptions = {};

    try {
        if (req.file) {
            if (!userPlan.media) return res.status(403).json({ message: 'Seu plano não permite envio de mídia.' });
            if (req.file.mimetype.startsWith('video') && !userPlan.video) return res.status(403).json({ message: 'Seu plano não permite envio de vídeos.' });

            mediaUrl = req.file.buffer;
            if(req.file.mimetype.startsWith('image')){
                mediaOptions = { image: mediaUrl, caption: message };
            } else if (req.file.mimetype.startsWith('video')){
                mediaOptions = { video: mediaUrl, caption: message };
            } else {
                mediaOptions = { document: mediaUrl, mimetype: req.file.mimetype, fileName: req.file.originalname };
            }
        }
        
        const numbers = to.split(',').map(n => n.trim());
        const remainingMessages = userPlan.msgDay - req.messagesSentToday;
        const numbersToSend = numbers.slice(0, remainingMessages);

        if (numbersToSend.length < numbers.length) {
            res.status(403).write(JSON.stringify({ message: `Limite de mensagens excedido. Apenas ${numbersToSend.length} mensagens serão enviadas.`}));
        }

        for (const number of numbersToSend) {
            const jid = `${number}@s.whatsapp.net`;
            if(req.file) {
                 await socket.sendMessage(jid, mediaOptions);
            } else {
                 await socket.sendMessage(jid, { text: message });
            }
            await new Message({ userId: req.userId, to: number, body: message, status: 'Enviada' }).save();
        }

        res.status(200).json({ message: `${numbersToSend.length} mensagens enviadas para a fila.` });

    } catch (error) {
        res.status(500).json({ message: 'Erro ao enviar mensagem', error: error.message });
    }
});


router.post('/payment', authMiddleware, upload.single('proofImage'), async (req, res) => {
    const { plan, amount, proofText } = req.body;
    let proofImageUrl = '';
    try {
        if (req.file) {
            const result = await new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream({ folder: "proofs" }, (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                });
                Readable.from(req.file.buffer).pipe(uploadStream);
            });
            proofImageUrl = result.secure_url;
        }
        const payment = new Payment({ userId: req.userId, plan, amount, proofText: proofText || '', proofImageUrl });
        await payment.save();
        res.status(201).json({ message: 'Solicitação de pagamento enviada.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao processar pagamento', error: error.message });
    }
});


router.get('/payment-numbers', (req, res) => {
    res.json({ mpesa: process.env.MPESA_NUMBER, emola: process.env.EMOLA_NUMBER });
});

router.get('/history', authMiddleware, async (req, res) => {
    const messages = await Message.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(200);
    res.json(messages);
});

router.get('/stats/dashboard', authMiddleware, async(req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const messagesByDay = await Message.aggregate([
        { $match: { userId: new mongoose.Types.ObjectId(req.userId), createdAt: { $gte: new Date(new Date().setDate(new Date().getDate() - 7)) } } },
        { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
    ]);

    const user = await User.findById(req.userId);
    const messagesSentToday = await Message.countDocuments({ userId: req.userId, createdAt: { $gte: today } });
    const planUsage = {
        sent: messagesSentToday,
        total: PLAN_LIMITS[user.plan].msgDay
    };
    
    res.json({ messagesByDay, planUsage });
});

router.post('/schedule', authMiddleware, planCheckMiddleware({ minPlan: 'Padrão' }), async (req, res) => {
    const { to, body, sendAt } = req.body;
    const scheduledMessage = new ScheduledMessage({ userId: req.userId, to, body, sendAt });
    await scheduledMessage.save();
    res.status(201).json({ message: 'Mensagem agendada com sucesso.' });
});

router.get('/schedule', authMiddleware, planCheckMiddleware({ minPlan: 'Padrão' }), async (req, res) => {
    const messages = await ScheduledMessage.find({ userId: req.userId, status: 'Pendente' }).sort({ sendAt: 1 });
    res.json(messages);
});

router.delete('/schedule/:id', authMiddleware, async (req, res) => {
    await ScheduledMessage.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    res.status(200).json({ message: 'Agendamento cancelado.' });
});

router.get('/utils/generate-numbers', authMiddleware, planCheckMiddleware({ minPlan: 'Premium' }), (req, res) => {
    const { country, areaCode, quantity } = req.query;
    const q = Math.min(parseInt(quantity) || 10, 500);
    const numbers = [];
    const prefixes = {
        MZ: ['84', '82', '83', '85', '86', '87'],
        BR: [`${areaCode}`],
        AO: ['91', '92', '93', '94', '99']
    };

    if (!prefixes[country] || (country === 'BR' && !areaCode)) return res.status(400).json({ message: 'País ou código de área inválido.' });
    
    for (let i = 0; i < q; i++) {
        const prefix = prefixes[country][Math.floor(Math.random() * prefixes[country].length)];
        const suffix = Math.floor(1000000 + Math.random() * 9000000).toString();
        if(country === 'BR') {
            numbers.push(`55${prefix}9${suffix}`);
        } else {
            numbers.push(`${prefix}${suffix}`);
        }
    }
    res.json(numbers);
});

// ADMIN ROUTES
router.get('/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    const users = await User.find({ isAdmin: false }).select('-password');
    res.json(users);
});

router.get('/admin/payments', authMiddleware, adminMiddleware, async (req, res) => {
    const payments = await Payment.find().populate('userId', 'username').sort({ createdAt: -1 });
    res.json(payments);
});

router.post('/admin/payments/approve/:paymentId', authMiddleware, adminMiddleware, async (req, res) => {
    const payment = await Payment.findById(req.params.paymentId);
    if (!payment) return res.status(404).json({ message: 'Pagamento não encontrado.' });
    await User.findByIdAndUpdate(payment.userId, { plan: payment.plan, messageCount: 0 });
    payment.status = 'Aprovado';
    await payment.save();
    res.json({ message: 'Pagamento aprovado e plano atualizado.' });
});

router.post('/admin/payments/reject/:paymentId', authMiddleware, adminMiddleware, async (req, res) => {
    const payment = await Payment.findById(req.params.paymentId);
    payment.status = 'Rejeitado';
    await payment.save();
    res.json({ message: 'Pagamento rejeitado.' });
});

router.get('/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
    const totalMessages = await Message.countDocuments();
    const totalUsers = await User.countDocuments({ isAdmin: false });
    const messagesByPlan = await User.aggregate([
        { $match: { isAdmin: false } },
        { $group: { _id: "$plan", totalMessages: { $sum: "$messageCount" } } }
    ]);
    res.json({ totalMessages, totalUsers, messagesByPlan });
});

module.exports = { router, setSocketIo, sessions };