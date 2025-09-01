// server.js — backend único (Express + Prisma + BullMQ)
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import { Queue, Worker } from "bullmq";

// ===== Config =====
const env = {
  PORT: Number(process.env.PORT || 3000),
  JWT_SECRET: process.env.JWT_SECRET || "dev-secret",
  BCRYPT_ROUNDS: Number(process.env.BCRYPT_ROUNDS || 10),
  REDIS_URL: process.env.REDIS_URL || "redis://localhost:6379",
};

const prisma = new PrismaClient();

// ===== App =====
const app = express();
app.use(helmet());
app.use(
  cors({
    origin: [
      "http://localhost:5173", 
      "https://frontrecompensa-production.up.railway.app"
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);


app.use(express.json({ limit: "4mb" }));


// ===== Utils =====
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, env.JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ erro: "não autorizado" });
  }
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = (v) => (v * Math.PI) / 180;
  const R = 6371; // km
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// ===== Moderação (heurística MVP) =====
const BANNED = [
  "matar", "assassinar", "sequestro", "drogas", "invadir conta", "hackear",
  "endereco residencial de", "cpf de", "chantagem", "espionar",
  "criança", "pornografia", "explosivo", "arma", "branco/negro/gay",
];
const SENSITIVE = [
  "descobrir endereco", "seguir pessoa", "monitorar", "localizar pessoa",
  "documentos pessoais", "senha", "codigo 2fa", "dados bancarios",
];
function evaluateText(text) {
  const t = String(text || "").toLowerCase();
  const flags = [];
  let score = 0;
  for (const w of BANNED) if (t.includes(w)) { flags.push(`BANNED:${w}`); score += 100; }
  for (const w of SENSITIVE) if (t.includes(w)) { flags.push(`SENSITIVE:${w}`); score += 30; }
  if (/\b(\d{1,3}(\.\d{3})*|\d+)(,\d{2})?\b/.test(t)) score += 5; // valores
  if (t.includes("urgente") || t.includes("imediato")) score += 5;
  return { score, flags };
}

// ===== BullMQ (fila + worker) =====
const moderationQueue = new Queue("moderation", { connection: { url: env.REDIS_URL } });
async function enqueueRecompensaModeration(recompensaId) {
  await moderationQueue.add(
    "recompensa",
    { recompensaId },
    { attempts: 3, removeOnComplete: true, removeOnFail: true }
  );
}

new Worker(
  "moderation",
  async (job) => {
    const { recompensaId } = job.data;
    const r = await prisma.recompensa.findUnique({ where: { id: recompensaId } });
    if (!r) return;

    const fullText = `${r.titulo}\n${r.descricao}`;
    const { score, flags } = evaluateText(fullText);

    if (flags.some((f) => f.startsWith("BANNED"))) {
      await prisma.recompensa.update({
        where: { id: r.id },
        data: { status: "BANIDA", riskScore: score },
      });
      await prisma.moderacaoEvento.create({
        data: {
          recompensaId: r.id,
          recursoTipo: "Recompensa",
          recursoId: r.id,
          acao: "REJEITAR",
          motivo: flags.join(", "),
        },
      });
      return;
    }

    if (score >= 40) {
      await prisma.moderacaoEvento.create({
        data: {
          recompensaId: r.id,
          recursoTipo: "Recompensa",
          recursoId: r.id,
          acao: "AJUSTAR",
          motivo: flags.join(", "),
        },
      });
      return;
    }

    await prisma.recompensa.update({
      where: { id: r.id },
      data: { status: "PUBLICADA", riskScore: score },
    });
    await prisma.moderacaoEvento.create({
      data: {
        recompensaId: r.id,
        recursoTipo: "Recompensa",
        recursoId: r.id,
        acao: "APROVAR",
        motivo: "auto",
      },
    });
  },
  { connection: { url: env.REDIS_URL } }
);

console.log("👮 Worker de moderação iniciado (no mesmo processo)");

// ===== Rotas =====
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/auth/signup", async (req, res) => {
  const { nomeCompleto, email, senha, telefone, cpf, dataNascimento, endereco } = req.body;
  try {
    const existente = await prisma.usuario.findUnique({ where: { email } });
    if (existente) return res.status(400).json({ erro: "Email já cadastrado" });

    const cpfExistente = await prisma.usuario.findUnique({ where: { cpf } });
    if (cpfExistente) return res.status(400).json({ erro: "CPF já cadastrado" });

    const senhaHash = await bcrypt.hash(senha, env.BCRYPT_ROUNDS);
    const user = await prisma.usuario.create({
      data: {
        nomeCompleto,
        email,
        senhaHash,
        telefone,
        cpf,
        dataNascimento: new Date(dataNascimento),
        endereco,
        kycStatus: "PENDENTE",
      },
    });

    res.json({ id: user.id, email: user.email, nome: user.nomeCompleto });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});


app.post("/auth/login", async (req, res) => {
  const { email, senha } = req.body;
  try {
    const user = await prisma.usuario.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ erro: "Credenciais inválidas" });
    const ok = await bcrypt.compare(senha, user.senhaHash);
    if (!ok) return res.status(401).json({ erro: "Credenciais inválidas" });
    const token = jwt.sign({ sub: user.id }, env.JWT_SECRET, { expiresIn: "7d" });
    res.json({
  token,
  user: {
    id: user.id,
    email: user.email,
    nomeCompleto: user.nomeCompleto // ✅ agora o frontend vai receber corretamente
  }
});

  } catch (e) {
    res.status(401).json({ erro: e.message });
  }
});

// criar recompensa
app.post("/recompensas", requireAuth, async (req, res) => {
  try {
    const {
      titulo, descricao, categoria,
      valorCentavos, prazoISO,
      scope, uf, municipioIbge, latitude, longitude, raioMetros,
    } = req.body;

    const r = await prisma.recompensa.create({
      data: {
        criadorId: req.userId,
        titulo, descricao, categoria,
        valorCentavos, prazoISO,
        scope, uf, municipioIbge,
        latitude, longitude, raioMetros,
        status: "EM_REVISAO",
      },
    });

    await enqueueRecompensaModeration(r.id);
    res.json({ id: r.id, status: r.status });
  } catch (e) {
    res.status(400).json({ erro: e.message });
  }
});

// feed
app.get("/recompensas", async (req, res) => {
  const { scope, uf, municipioIbge, lat, lon, raioKm, categoria } = req.query;

  let base = await prisma.recompensa.findMany({
    where: {
      status: "PUBLICADA",
      ...(categoria ? { categoria: { contains: String(categoria), mode: "insensitive" } } : {}),
      ...(scope ? { scope } : {}),
    },
    orderBy: { criadoEm: "desc" },
    take: 200,
  });

  if (scope === "UF" && uf) base = base.filter((r) => r.uf === uf);
  if (scope === "MUNICIPIO" && municipioIbge) base = base.filter((r) => r.municipioIbge === municipioIbge);

  if (scope === "RAIO" && lat && lon && raioKm) {
    const lat0 = parseFloat(lat);
    const lon0 = parseFloat(lon);
    const raio = parseFloat(raioKm);
    base = base.filter((r) => {
      if (r.latitude == null || r.longitude == null) return false;
      const d = haversineKm(lat0, lon0, r.latitude, r.longitude);
      const lim = (r.raioMetros || 0) / 1000;
      return d <= Math.max(raio, lim);
    });
  }

  res.json(base.map((r) => ({
    id: r.id,
    titulo: r.titulo,
    categoria: r.categoria,
    valorCentavos: r.valorCentavos,
    scope: r.scope,
    uf: r.uf,
    municipioIbge: r.municipioIbge,
    latitude: r.latitude,
    longitude: r.longitude,
    criadoEm: r.criadoEm,
  })));
});

// rota raiz para teste rápido
app.get("/", (_req, res) => {
  res.json({
    ok: true,
    message: "🚀 Backend Recompensa ativo",
    timestamp: new Date().toISOString(),
  });
});


// start
app.listen(env.PORT, () => console.log(`🌐 HTTP on :${env.PORT}`));
