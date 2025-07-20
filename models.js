const mongoose = require('mongoose');
const { Schema } = mongoose;

const planDetails = {
  type: String,
  enum: ['Free', 'Padrão', 'Premium'],
  default: 'Free'
};

const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  plan: planDetails,
  messageCount: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
  whatsappSession: { type: String, default: '' },
  whatsappConnected: { type: Boolean, default: false }
}, { timestamps: true });

const messageSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: String, required: true },
  body: { type: String, required: true },
  mediaUrl: { type: String },
  status: { type: String, enum: ['Enviada', 'Falhou', 'Pendente'], default: 'Pendente' },
}, { timestamps: true });

const paymentSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  plan: planDetails,
  proofText: { type: String },
  proofImageUrl: { type: String },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['Pendente', 'Aprovado', 'Rejeitado'], default: 'Pendente' }
}, { timestamps: true });

const scheduledMessageSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    to: { type: String, required: true },
    body: { type: String, required: true },
    mediaUrl: { type: String },
    sendAt: { type: Date, required: true },
    status: { type: String, enum: ['Pendente', 'Enviada', 'Cancelada'], default: 'Pendente' },
}, { timestamps: true });


const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Payment = mongoose.model('Payment', paymentSchema);
const ScheduledMessage = mongoose.model('ScheduledMessage', scheduledMessageSchema);

module.exports = {
  User,
  Message,
  Payment,
  ScheduledMessage
};