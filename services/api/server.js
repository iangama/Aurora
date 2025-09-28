const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'aurora-secret';

app.get('/healthz', (_req, res) => res.json({ ok: true }));

const creds = z.object({ email: z.string().email(), password: z.string().min(6).max(128) });

app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = creds.parse(req.body || {});
    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) return res.status(409).json({ ok: false, msg: 'email já existe' });
    const hash = bcrypt.hashSync(password, 10);
    const user = await prisma.user.create({ data: { email, password: hash } });
    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token });
  } catch (e) {
    if (e?.issues) return res.status(400).json({ ok:false, msg:'payload inválido', issues:e.issues });
    console.error(e);
    res.status(500).json({ ok:false, msg:'erro interno' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = creds.parse(req.body || {});
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ ok:false, msg:'credenciais inválidas' });
    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.status(401).json({ ok:false, msg:'credenciais inválidas' });
    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ok: true, token });
  } catch (e) {
    if (e?.issues) return res.status(400).json({ ok:false, msg:'payload inválido', issues:e.issues });
    console.error(e);
    res.status(500).json({ ok:false, msg:'erro interno' });
  }
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ ok:false, msg:'token ausente' });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ ok:false, msg:'token inválido' });
  }
}

app.get('/events', async (_req, res) => {
  const events = await prisma.event.findMany({ orderBy: { createdAt: 'desc' } });
  res.json({ ok:true, events });
});

const eventSchema = z.object({
  title: z.string().min(1).max(140),
  date: z.string().transform((s)=>new Date(s)),
  location: z.string().min(1).max(200)
});

app.post('/events', auth, async (req, res) => {
  try {
    const { title, date, location } = eventSchema.parse(req.body || {});
    const ev = await prisma.event.create({
      data: { title, date, location, ownerId: req.user.sub }
    });
    res.json({ ok:true, event: ev });
  } catch (e) {
    if (e?.issues) return res.status(400).json({ ok:false, msg:'payload inválido', issues:e.issues });
    console.error(e);
    res.status(500).json({ ok:false, msg:'erro interno' });
  }
});

const regSchema = z.object({ eventId: z.string().min(1) });

app.post('/registrations', auth, async (req, res) => {
  try {
    const { eventId } = regSchema.parse(req.body || {});
    const reg = await prisma.registration.create({
      data: { eventId, userId: req.user.sub }
    });
    res.json({ ok:true, registration: reg });
  } catch (e) {
    if (e?.code === 'P2002') return res.status(409).json({ ok:false, msg:'já inscrito neste evento' });
    if (e?.issues) return res.status(400).json({ ok:false, msg:'payload inválido', issues:e.issues });
    console.error(e);
    res.status(500).json({ ok:false, msg:'erro interno' });
  }
});

app.listen(PORT, () => console.log(`aurora-api on ${PORT}`));
