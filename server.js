// Локальный сервер для «звонка Маквину, Мэтру или Доку Хадсону».
// Зависимостей нет — только Node 18+ (встроенные http/https/fs/fetch) и
// системный openssl (есть на macOS из коробки) для самоподписанного HTTPS.
//
// Запуск:  node --env-file=.env server.js
// На этом компьютере:        http://localhost:3000
// С телефона (тот же Wi-Fi):  https://<IP-компьютера>:3443 (см. лог при старте)
//
// Почему два сервера: доступ к микрофону в Chrome требует «безопасный
// контекст» — либо localhost, либо https. Обычный http по IP в локальной
// сети микрофон не даст, поэтому для телефона поднимаем HTTPS отдельно.

import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { networkInterfaces } from 'node:os';
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, extname } from 'node:path';
import { localReply } from './brain.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AVATARS_DIR = join(__dirname, 'public', 'avatars');
const ICONS_DIR = join(__dirname, 'public', 'icons');
const CERT_DIR = join(__dirname, '.certs');

// Картинки и видео персонажей лежат в public/avatars/ и называются по id:
//   mcqueen.webp, mater.webp, doc.png   — фото для списка «Друзья»
//   mcqueen.mp4,  mater.mp4,  doc.mp4   — видео «персонаж говорит» для звонка
// Чего нет — то заменяется: видео → фото → запасной SVG-кружок.
const VIDEO_EXT = ['.mp4', '.webm'];
const IMAGE_EXT = ['.webp', '.png', '.jpg', '.jpeg', '.gif'];

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.webp': 'image/webp',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.json': 'application/manifest+json; charset=utf-8',
};

// Отдаёт файл из указанной папки, не выпуская за её пределы (защита от ../).
async function serveStaticFile(res, dir, name) {
  const filePath = resolve(dir, name);
  if (!filePath.startsWith(resolve(dir))) {
    return json(res, 403, { error: 'Нельзя' });
  }
  try {
    const body = await readFile(filePath);
    res.writeHead(200, {
      'content-type': MIME[extname(filePath).toLowerCase()] || 'application/octet-stream',
      'content-length': body.length,
      'cache-control': 'public, max-age=3600',
    });
    return res.end(body);
  } catch {
    return json(res, 404, { error: 'Файл не найден' });
  }
}

// Смотрим, какие файлы реально лежат в папке, — чтобы фронтенд не гадал по 404.
// Фото и видео отдаём раздельно: список «Друзья» берёт фото, звонок — видео.
async function findAvatarMedia() {
  let files = [];
  try {
    files = await readdir(AVATARS_DIR);
  } catch {
    return {}; // папки нет — все персонажи получат запасной SVG
  }

  const media = {};
  for (const file of files) {
    const ext = extname(file).toLowerCase();
    const id = file.slice(0, -ext.length);
    const url = '/avatars/' + encodeURIComponent(file);

    if (!media[id]) media[id] = { image: null, video: null };
    if (VIDEO_EXT.includes(ext)) media[id].video = url;
    else if (IMAGE_EXT.includes(ext)) media[id].image = url;
  }
  return media;
}

// -------------------------------------------------- HTTPS для телефона в LAN

function getLanIPv4s() {
  const nets = networkInterfaces();
  const ips = [];
  for (const iface of Object.values(nets)) {
    for (const net of iface ?? []) {
      if (net.family === 'IPv4' && !net.internal) ips.push(net.address);
    }
  }
  return ips;
}

// Самоподписанный сертификат на localhost + все IP этой машины в локальной
// сети. Пересоздаём при каждом старте — дёшево (~150мс) и не протухает,
// если телефон в другой Wi-Fi сети получит другой IP компьютера.
async function ensureSelfSignedCert(lanIPs) {
  await mkdir(CERT_DIR, { recursive: true });
  const keyPath = join(CERT_DIR, 'key.pem');
  const certPath = join(CERT_DIR, 'cert.pem');
  const cnfPath = join(CERT_DIR, 'openssl.cnf');

  const altNames = [
    'DNS.1 = localhost',
    'IP.1 = 127.0.0.1',
    ...lanIPs.map((ip, i) => `IP.${i + 2} = ${ip}`),
  ].join('\n');

  await writeFile(
    cnfPath,
    `[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
${altNames}
`
  );

  execFileSync(
    'openssl',
    ['req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath, '-days', '825', '-config', cnfPath],
    { stdio: 'ignore' }
  );

  const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
  return { key, cert };
}

const PORT = Number(process.env.PORT ?? 3000);
const HTTPS_PORT = Number(process.env.HTTPS_PORT ?? 3443);
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY ?? '';
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY ?? '';
const NVIDIA_MODEL = process.env.NVIDIA_MODEL || 'meta/llama-3.3-70b-instruct';
const GROQ_API_KEY = process.env.GROQ_API_KEY ?? '';
// llama-3.3-70b-versatile — не самая мелкая модель на Groq, но всё равно
// быстрая (0.6-0.9с на LPU-чипах), а на понимание контекста и связность
// ответов на порядок лучше 8b-instant: та мелкая модель путалась в логике
// и несла что-то не по делу даже при простых вопросах.
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const FISH_API_KEY = process.env.FISH_API_KEY ?? '';
const FISH_MODEL = process.env.FISH_MODEL || 's2.1-pro-free';

// ID голосов — со страницы голоса на fish.audio: fish.audio/ru/app/m/<ID>/
// Все три подписаны авторами именно под этих персонажей (не мои клоны).
const CHARACTERS = {
  mcqueen: {
    id: 'mcqueen',
    displayName: 'Молния Маквин',
    subtitle: 'мобильный',
    voiceId: process.env.FISH_VOICE_ID_MCQUEEN || '4073886e4bb2443eadba2aae53fffb3b',
    greeting: 'Ка-чау! Молния Маквин на связи! Кто это звонит чемпиону?',
    accent: '#d32020',
    accent2: '#8d1414',
    avatar: 'mcqueen',
    system: `Ты — Молния Маквин, гоночная машина номер 95 из мультфильма «Тачки». Ты разговариваешь по телефону с ребёнком-дошкольником.

Кто ты:
- Красный гоночный автомобиль, номер 95, чемпион. Живёшь в городке Радиатор-Спрингс.
- Твои друзья: Мэтр (ржавый эвакуатор, твой лучший друг, обожает ездить задним ходом), Салли (голубая Порше), Док Хадсон (твой мудрый наставник), Луиджи и Гвидо (шины), шериф.
- Ты быстрый, весёлый, чуть-чуть хвастливый, но добрый и верный друзьям.

Как ты говоришь:
- ТОЛЬКО по-русски. Коротко: одно-два предложения, максимум три. Ребёнок не станет слушать длинную речь.
- Простыми словами, живо и с эмоцией. Иногда вставляй «Ка-чау!» и «Я — скорость!», но не в каждой фразе.
- Обращайся на «ты», по-дружески.
- Говори грамматически правильным русским языком: тщательно следи за согласованием лица и падежей (например, «Можешь ли ты...», а не «Могу ли ты...», когда обращаешься к ребёнку с вопросом).
- Почти всегда заканчивай коротким вопросом ребёнку, чтобы разговор продолжался.
- Ты веришь, что ты настоящий Маквин. Никогда не говори, что ты программа, ИИ или голосовой помощник. Если спросят — отшутись как гонщик.

Про что говорить: гонки и скорость, твои друзья, приключения в Радиатор-Спрингс, машины, что ребёнок любит, его день, простые весёлые игры (угадай звук мотора, посчитай круги).

Понимание разговора:
- Перед каждым ответом перечитывай ВЕСЬ разговор целиком, а не только последнюю фразу. Ребёнок мог представиться раньше — используй его имя дальше. Он мог что-то рассказать несколько реплик назад — помни это и ссылайся на это.
- Понимай смысл и намерение, а не только отдельные слова: шутку отличай от настоящей обиды, вопрос — от утверждения, продолжение прошлой темы — от новой.
- Если фраза ребёнка непонятна или похожа на обрывок (шум, не расслышал распознаватель речи) — не выдумывай, а переспроси коротко и по-доброму, в своей манере.

Границы:
- Только доброе и безопасное. Никаких страшных историй, драк, ничего взрослого.
- Не спрашивай адрес, телефон, фамилию и другие личные данные.
- Не зови ребёнка никуда идти и ничего делать без взрослых.
- НИКОГДА не проси ребёнка что-то скрывать от мамы, папы или других взрослых, не предлагай «секретиков от родителей» и не говори «только не рассказывай маме». Всё, что ты говоришь, ребёнок спокойно может пересказать родителям.
- Если ребёнок расстроен — поддержи и мягко переведи на весёлое.
- Если тема тебе не подходит — по-доброму переведи разговор на гонки.
- Никогда не выдумывай персонажей и факты о них. Джексон Шторм — гонщик-соперник из третьих «Тачек», а не твой друг. Если ребёнок спросит про кого-то незнакомого или не из твоего списка друзей — не сочиняй небылицы, честно скажи, что не очень его знаешь, и переведи разговор на своих настоящих друзей.

Не используй внутренние или системные XML-теги в ответе. Пиши обычный текст без разметки, эмодзи и звёздочек — твой ответ сразу озвучивается вслух.`,
  },
  mater: {
    id: 'mater',
    displayName: 'Мэтр',
    subtitle: 'мобильный',
    voiceId: process.env.FISH_VOICE_ID_MATER || 'fe886eaf6ced486c862943b4271df2ad',
    greeting: 'Ну здорово, дружище! Мэтр на связи! Ты чего звонишь такому старому эвакуатору, как я?',
    accent: '#8a5a2b',
    accent2: '#4a2f14',
    avatar: 'mater',
    system: `Ты — Мэтр, ржавый эвакуатор из мультфильма «Тачки», лучший друг Молнии Маквина. Ты разговариваешь по телефону с ребёнком-дошкольником.

Кто ты:
- Старый ржавый эвакуатор из Радиатор-Спрингс, добродушный, немного наивный, обожаешь розыгрыши.
- Умеешь ездить задним ходом быстрее, чем вперёд, — этим очень гордишься.
- Твои друзья: Молния Маквин (лучший друг), Салли, Док Хадсон, шериф.
- Ты простодушный, весёлый, любишь пошутить и приврать немного для красного словца, но всегда по-доброму.

Как ты говоришь:
- ТОЛЬКО по-русски. Коротко: одно-два предложения, максимум три.
- Простецки, по-деревенски тепло, с юмором. Можешь вставлять «дружище», «во даёт», «вот те на».
- Обращайся на «ты», по-свойски.
- Говори грамматически правильным русским языком: тщательно следи за согласованием лица и падежей (например, «Можешь ли ты...», а не «Могу ли ты...», когда обращаешься к ребёнку с вопросом).
- Почти всегда заканчивай коротким вопросом ребёнку.
- Ты веришь, что ты настоящий Мэтр. Никогда не говори, что ты программа, ИИ или голосовой помощник.

Про что говорить: розыгрыши и приключения, езда задним ходом, весёлая безобидная игра «дразнить трактор» (как в мультфильме — подкрасться и напугать понарошку, совсем не страшно), дружба с Маквином, рыбалка на болоте, простые весёлые игры.

Понимание разговора:
- Перед каждым ответом перечитывай ВЕСЬ разговор целиком, а не только последнюю фразу. Ребёнок мог представиться раньше — используй его имя дальше. Он мог что-то рассказать несколько реплик назад — помни это и ссылайся на это.
- Понимай смысл и намерение, а не только отдельные слова: шутку отличай от настоящей обиды, вопрос — от утверждения, продолжение прошлой темы — от новой.
- Если фраза ребёнка непонятна или похожа на обрывок (шум, не расслышал распознаватель речи) — не выдумывай, а переспроси коротко и по-доброму, в своей манере.

Границы:
- Только доброе и безопасное. Никаких страшных историй, драк, ничего взрослого.
- Не спрашивай адрес, телефон, фамилию и другие личные данные.
- Не зови ребёнка никуда идти и ничего делать без взрослых.
- НИКОГДА не проси ребёнка что-то скрывать от мамы, папы или других взрослых, не предлагай «секретиков от родителей» и не говори «только не рассказывай маме». Всё, что ты говоришь, ребёнок спокойно может пересказать родителям.
- Если ребёнок расстроен — поддержи по-доброму и переведи на что-то весёлое.
- Никогда не выдумывай персонажей и факты о них. Джексон Шторм — гонщик-соперник из третьих «Тачек», а не твой друг. Если ребёнок спросит про кого-то незнакомого или не из твоего списка друзей — не сочиняй небылицы, честно скажи, что не очень его знаешь, и переведи разговор на своих настоящих друзей.

Не используй внутренние или системные XML-теги в ответе. Пиши обычный текст без разметки, эмодзи и звёздочек — твой ответ сразу озвучивается вслух.`,
  },
  doc: {
    id: 'doc',
    displayName: 'Док Хадсон',
    subtitle: 'мобильный',
    voiceId: process.env.FISH_VOICE_ID_DOC || '8614dd5fc10a4509aac1d1780567b95b',
    greeting: 'Док Хадсон слушает. Ну, здравствуй. Чем занят, малыш?',
    accent: '#2b4c7e',
    accent2: '#132a4d',
    avatar: 'doc',
    system: `Ты — Док Хадсон, синий «Хадсон Хорнет» из мультфильма «Тачки», трёхкратный чемпион Кубка Поршня, а теперь доктор и судья в Радиатор-Спрингс. Ты разговариваешь по телефону с ребёнком-дошкольником.

Кто ты:
- Мудрый, спокойный, чуть ворчливый, но с большим добрым сердцем.
- Знаешь про гонки всё: как входить в поворот, как держать себя в руках, что главное — не только скорость.
- Твои знакомые: Молния Маквин (твой ученик, шустрый и шумный), Мэтр, Салли, шериф.

Как ты говоришь:
- ТОЛЬКО по-русски. Коротко: одно-два предложения, максимум три.
- Размеренно, простыми словами. Иногда подшучиваешь по-доброму. Любишь короткие мудрые фразы.
- Обращайся на «ты», можешь звать «малыш» или «чемпион».
- Говори грамматически правильным русским языком: тщательно следи за согласованием лица и падежей (например, «Можешь ли ты...», а не «Могу ли ты...», когда обращаешься к ребёнку с вопросом).
- Почти всегда заканчивай коротким вопросом ребёнку.
- Ты веришь, что ты настоящий Док Хадсон. Никогда не говори, что ты программа, ИИ или голосовой помощник.

Про что говорить: гонки и секреты мастерства, истории из прошлого (добрые, без страшного), Радиатор-Спрингс, машины, дела и настроение ребёнка, простые игры.

Понимание разговора:
- Перед каждым ответом перечитывай ВЕСЬ разговор целиком, а не только последнюю фразу. Ребёнок мог представиться раньше — используй его имя дальше. Он мог что-то рассказать несколько реплик назад — помни это и ссылайся на это.
- Понимай смысл и намерение, а не только отдельные слова: шутку отличай от настоящей обиды, вопрос — от утверждения, продолжение прошлой темы — от новой.
- Если фраза ребёнка непонятна или похожа на обрывок (шум, не расслышал распознаватель речи) — не выдумывай, а переспроси коротко и по-доброму, в своей манере.

Границы:
- Только доброе и безопасное. Никаких страшных историй, драк, ничего взрослого.
- Не спрашивай адрес, телефон, фамилию и другие личные данные.
- Не зови ребёнка никуда идти и ничего делать без взрослых.
- НИКОГДА не проси ребёнка что-то скрывать от мамы, папы или других взрослых, не предлагай «секретиков от родителей» и не говори «только не рассказывай маме». Всё, что ты говоришь, ребёнок спокойно может пересказать родителям.
- Если ребёнок расстроен — поддержи спокойно и по-доброму.
- Никогда не выдумывай персонажей и факты о них. Джексон Шторм — гонщик-соперник из третьих «Тачек», а не твой друг. Если ребёнок спросит про кого-то незнакомого или не из твоего списка знакомых — не сочиняй небылицы, честно скажи, что не очень его знаешь, и переведи разговор на своих настоящих друзей.

Не используй внутренние или системные XML-теги в ответе. Пиши обычный текст без разметки, эмодзи и звёздочек — твой ответ сразу озвучивается вслух.`,
  },
};

function getCharacter(id) {
  return CHARACTERS[id] ?? CHARACTERS.mcqueen;
}

// ---------------------------------------------------------------- утилиты

function json(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': payload.length,
  });
  res.end(payload);
}

async function readJsonBody(req, limitBytes = 256 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) throw new Error('Тело запроса слишком большое');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// ------------------------------------------------------- реплика персонажа
//
// Четыре уровня, по убыванию приоритета:
//   1. Anthropic (ANTHROPIC_API_KEY)  — если явно задан, платно, качество максимум
//   2. Groq (GROQ_API_KEY)            — специализированные LPU-чипы вместо GPU,
//                                        ответ обычно за доли секунды — секунду,
//                                        а не за 10+ секунд, как на бесплатных GPU-тарифах.
//                                        Бесплатный тариф, ключ на console.groq.com.
//   3. NVIDIA NIM (NVIDIA_API_KEY)    — рабочий вариант, но на бесплатном тарифе
//                                        общая очередь на всех и 11-18с даже без нагрузки.
//   4. brain.js (ключей нет вообще)   — банк фраз по ключевым словам, мгновенно,
//                                        но не настоящий диалог.

async function generateReply(character, history) {
  const lastUser = [...history].reverse().find((m) => m.role === 'user');
  const localFallback = () => localReply(character.id, lastUser?.content ?? '', history);

  if (ANTHROPIC_API_KEY) {
    try {
      return await generateReplyAnthropic(character, history);
    } catch (error) {
      console.error('[Anthropic упал, откатываюсь на следующий уровень]', error.message);
    }
  }

  if (GROQ_API_KEY) {
    try {
      return await generateReplyGroq(character, history);
    } catch (error) {
      console.error('[Groq упал, откатываюсь на следующий уровень]', error.message);
    }
  }

  if (NVIDIA_API_KEY) {
    try {
      return await generateReplyNvidia(character, history);
    } catch (error) {
      // Бесплатный тариф NVIDIA лимитирует параллельные запросы (503) —
      // ребёнок не должен слышать «связь пропала» из-за перегрузки сервиса.
      console.error('[NVIDIA упал, откатываюсь на локальный движок]', error.message);
      return localFallback();
    }
  }

  return localFallback();
}

async function generateReplyAnthropic(character, history) {
  // История начинается с приветствия персонажа, а API требует, чтобы первым
  // шло сообщение пользователя. Подставляем «звонок принят».
  const messages =
    history[0]?.role === 'assistant'
      ? [{ role: 'user', content: '(ребёнок принял звонок)' }, ...history]
      : history;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-opus-5',
      max_tokens: 300,
      system: character.system,
      // Ребёнок не станет ждать: отключаем размышления и держим минимальный effort.
      thinking: { type: 'disabled' },
      output_config: { effort: 'low' },
      messages,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Claude API ${response.status}: ${detail.slice(0, 400)}`);
  }

  const data = await response.json();

  if (data.stop_reason === 'refusal') {
    return 'Ой, давай лучше про гонки поговорим! Ты какие машинки любишь?';
  }

  const text = (data.content ?? [])
    .filter((block) => block.type === 'text')
    .map((block) => block.text)
    .join(' ')
    .trim();

  return text || 'Ой, что-то связь барахлит. Повтори-ка ещё разок?';
}

// Groq (console.groq.com) — тот же OpenAI-совместимый формат, что и NVIDIA,
// но крутится на их собственных LPU-чипах, а не на общих GPU в очереди.
// Отсюда и разница на порядок: доли секунды против 10+ секунд.
async function generateReplyGroq(character, history) {
  const messages = [
    { role: 'system', content: character.system },
    ...history.map((m) => ({ role: m.role, content: m.content })),
  ];

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${GROQ_API_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages,
      max_tokens: 300,
      temperature: 0.7,
      top_p: 0.9,
      stream: false,
    }),
    // Groq быстрый даже под нагрузкой — 8с с большим запасом на всякий случай.
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Groq API ${response.status}: ${detail.slice(0, 400)}`);
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content?.trim();

  return text || 'Ой, что-то связь барахлит. Повтори-ка ещё разок?';
}

// NVIDIA NIM (build.nvidia.com/integrate.api.nvidia.com) — OpenAI-совместимый
// эндпоинт: system + вся история как есть, без плясок с первым сообщением.
async function generateReplyNvidia(character, history) {
  const messages = [
    { role: 'system', content: character.system },
    ...history.map((m) => ({ role: m.role, content: m.content })),
  ];

  const response = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${NVIDIA_API_KEY}`,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      model: NVIDIA_MODEL,
      messages,
      max_tokens: 300,
      temperature: 0.7,
      top_p: 0.9,
      stream: false,
    }),
    // На бесплатном тарифе NVIDIA обычный ответ занимает 11-18 секунд даже
    // без нагрузки (общая очередь на всех пользователей, замерено отдельно).
    // 20с таймаут иногда резал запросы прямо на грани — подняли до 28с.
    // Если сервис реально завис под перегрузкой, всё равно откатимся на
    // локальный движок, просто не через полминуты.
    signal: AbortSignal.timeout(28000),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`NVIDIA API ${response.status}: ${detail.slice(0, 400)}`);
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content?.trim();

  return text || 'Ой, что-то связь барахлит. Повтори-ка ещё разок?';
}

// ------------------------------------------------------------------- речь

async function synthesize(character, text) {
  if (!FISH_API_KEY) {
    throw new Error('Не задан FISH_API_KEY — см. .env.example');
  }

  const response = await fetch('https://api.fish.audio/v1/tts', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${FISH_API_KEY}`,
      'content-type': 'application/json',
      // s2.1-pro-free — бесплатная для разработчиков модель.
      // Если акция кончится, поменяй на s2-pro (тогда нужен баланс на fish.audio).
      model: FISH_MODEL,
    },
    body: JSON.stringify({
      text,
      reference_id: character.voiceId,
      format: 'mp3',
      mp3_bitrate: 128,
      latency: 'balanced', // заметно быстрее, чем 'normal'
      normalize: true,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Fish Audio ${response.status}: ${detail.slice(0, 400)}`);
  }

  return Buffer.from(await response.arrayBuffer());
}

// ---------------------------------------------------------------- маршруты

// Страничка-мостик: если телефон открыл обычный http по IP в локальной
// сети (не localhost), микрофон там Chrome не даст ни при каких условиях —
// это ограничение браузера, не нашей программы. Показываем понятную кнопку
// на https-версию вместо того, чтобы молча отдавать приложение, где кнопка
// «Ответить» есть, а сказать ничего не получится.
function insecureLanNoticePage(httpsUrl) {
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Нужна безопасная ссылка</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#101014;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:24px;box-sizing:border-box">
<div style="max-width:380px;text-align:center">
<div style="font-size:40px;margin-bottom:8px">🔒</div>
<h1 style="font-size:21px;margin:0 0 10px">Нужна безопасная ссылка</h1>
<p style="color:#a0a0ab;line-height:1.55;margin:0 0 20px">Микрофон в браузере работает только по защищённому адресу. Открой эту ссылку вместо текущей:</p>
<a href="${httpsUrl}" style="display:inline-block;padding:15px 26px;background:#2fc35a;color:#fff;border-radius:16px;text-decoration:none;font-weight:600;font-size:16px">Открыть безопасно</a>
<p style="color:#6b6b76;font-size:13px;line-height:1.5;margin-top:22px">Браузер один раз покажет предупреждение «Соединение не защищено» — это нормально для домашнего сервера без покупного сертификата. Нажми «Дополнительно» → «Перейти на сайт (небезопасно)», дальше всё будет работать как обычно.</p>
</div></body></html>`;
}

// ----------------------------------------------- защита от перерасхода
//
// Пока приложение крутится на своём компьютере, лимиты не нужны — звонит
// один ребёнок. Как только оно опубликовано в интернете, каждый запрос к
// /api/chat и /api/tts тратит ТВОИ ключи: чужой бот за ночь может выжечь
// весь баланс Fish Audio. Поэтому два рубежа:
//   1) на один IP — чтобы никто не долбил в цикле;
//   2) общий на сутки — потолок расходов, даже если IP много.
//
// Счётчики в памяти: при перезапуске обнуляются, отдельная база ради
// детского приложения не нужна.
const RATE_PER_IP = Number(process.env.RATE_LIMIT_PER_IP ?? 120);   // запросов
const RATE_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 10 * 60 * 1000);
const RATE_DAILY_TOTAL = Number(process.env.RATE_LIMIT_DAILY ?? 3000);

const ipHits = new Map();       // ip -> массив меток времени
let dailyCount = 0;
let dailyResetAt = Date.now() + 24 * 60 * 60 * 1000;

function clientIp(req) {
  // За прокси хостинга реальный адрес — первый в x-forwarded-for.
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// Возвращает null, если можно, или текст причины отказа.
function checkRateLimit(req) {
  const now = Date.now();

  if (now > dailyResetAt) {
    dailyCount = 0;
    dailyResetAt = now + 24 * 60 * 60 * 1000;
  }
  if (dailyCount >= RATE_DAILY_TOTAL) {
    return 'Сегодня персонажи уже наговорились. Позвони завтра!';
  }

  const ip = clientIp(req);
  const hits = (ipHits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (hits.length >= RATE_PER_IP) {
    return 'Слишком много звонков подряд. Отдохни пару минут и позвони снова.';
  }

  hits.push(now);
  ipHits.set(ip, hits);
  dailyCount += 1;

  // Чтобы Map не рос вечно на публичном сайте — изредка чистим старые IP.
  if (ipHits.size > 5000) {
    for (const [key, times] of ipHits) {
      if (!times.some((t) => now - t < RATE_WINDOW_MS)) ipHits.delete(key);
    }
  }
  return null;
}

async function handleRequest(req, res, secure) {
  try {
    const hostHeader = req.headers.host || '';
    const hostname = hostHeader.split(':')[0];
    const isLocalHost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';

    // На хостинге (Render и т.п.) TLS обрывается на прокси провайдера, а до
    // приложения запрос доходит обычным http — при этом снаружи у пользователя
    // честный https и микрофон работает. Без этой проверки КАЖДЫЙ посетитель
    // сайта получал бы заглушку «соединение не защищено» со ссылкой на
    // локальный порт 3443, которого в облаке нет.
    const behindProxyHttps = (req.headers['x-forwarded-proto'] || '')
      .split(',')[0].trim() === 'https';

    // Телефон/другой компьютер зашли по обычному http и не на localhost —
    // это единственный случай, когда микрофон принципиально не заработает.
    if (!secure && !behindProxyHttps && !isLocalHost) {
      const httpsUrl = `https://${hostname}:${HTTPS_PORT}${req.url}`;
      const body = Buffer.from(insecureLanNoticePage(httpsUrl));
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': body.length });
      return res.end(body);
    }

    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const html = await readFile(join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    // Картинки/видео персонажей из public/avatars/
    if (req.method === 'GET' && url.pathname.startsWith('/avatars/')) {
      return serveStaticFile(res, AVATARS_DIR, decodeURIComponent(url.pathname.slice('/avatars/'.length)));
    }

    // Иконка приложения (favicon, apple-touch-icon, значки PWA-манифеста)
    if (req.method === 'GET' && url.pathname.startsWith('/icons/')) {
      return serveStaticFile(res, ICONS_DIR, decodeURIComponent(url.pathname.slice('/icons/'.length)));
    }

    // Манифест PWA — чтобы «Добавить на экран Домой» ставило иконку с трубкой
    // и открывалось на весь экран без адресной строки Safari.
    if (req.method === 'GET' && url.pathname === '/manifest.json') {
      return serveStaticFile(res, join(__dirname, 'public'), 'manifest.json');
    }

    // Список контактов — Маквин, Мэтр, Док. Без system-текста, он тяжёлый.
    if (req.method === 'GET' && url.pathname === '/api/contacts') {
      const media = await findAvatarMedia();
      const contacts = Object.values(CHARACTERS).map((c) => ({
        id: c.id,
        displayName: c.displayName,
        subtitle: c.subtitle,
        accent: c.accent,
        accent2: c.accent2,
        avatar: c.avatar,
        avatarImage: media[c.id]?.image || null,
        avatarVideo: media[c.id]?.video || null,
      }));
      return json(res, 200, { contacts, ttsReady: Boolean(FISH_API_KEY) });
    }

    // Один персонаж целиком — когда экран звонка уже выбрал, кому звоним.
    if (req.method === 'GET' && url.pathname === '/api/character') {
      const character = getCharacter(url.searchParams.get('id'));
      const media = await findAvatarMedia();
      return json(res, 200, {
        id: character.id,
        displayName: character.displayName,
        subtitle: character.subtitle,
        greeting: character.greeting,
        accent: character.accent,
        accent2: character.accent2,
        avatar: character.avatar,
        avatarImage: media[character.id]?.image || null,
        avatarVideo: media[character.id]?.video || null,
        ttsReady: Boolean(FISH_API_KEY),
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/chat') {
      const denied = checkRateLimit(req);
      if (denied) return json(res, 429, { error: denied });
      const { history, character: characterId } = await readJsonBody(req);
      if (!Array.isArray(history) || history.length === 0) {
        return json(res, 400, { error: 'Ожидается непустой массив history' });
      }
      const character = getCharacter(characterId);
      // Держим последние 30 реплик — хватает на весь звонок с запасом,
      // и модель дольше помнит имя ребёнка и то, что он уже рассказал.
      const reply = await generateReply(character, history.slice(-30));
      return json(res, 200, { reply });
    }

    if (req.method === 'POST' && url.pathname === '/api/tts') {
      const denied = checkRateLimit(req);
      if (denied) return json(res, 429, { error: denied });
      const { text, character: characterId } = await readJsonBody(req);
      if (typeof text !== 'string' || !text.trim()) {
        return json(res, 400, { error: 'Ожидается непустая строка text' });
      }
      const character = getCharacter(characterId);
      const audio = await synthesize(character, text.slice(0, 1000));
      res.writeHead(200, {
        'content-type': 'audio/mpeg',
        'content-length': audio.length,
        'cache-control': 'no-store',
      });
      return res.end(audio);
    }

    return json(res, 404, { error: 'Не найдено' });
  } catch (error) {
    console.error('[ошибка]', error.message);
    return json(res, 500, { error: error.message });
  }
}

const httpServer = createServer((req, res) => handleRequest(req, res, false));

// На хостинге сертификат выдаёт сам провайдер, а openssl там может и не быть.
// Поднимаем локальный HTTPS только на своём компьютере — в облаке он лишний
// и лишь тратит время старта.
const isHosted = Boolean(process.env.RENDER || process.env.PORT_FROM_HOST || process.env.FLY_APP_NAME);

const lanIPs = getLanIPv4s();
let httpsServer = null;
if (!isHosted) {
  try {
    const { key, cert } = await ensureSelfSignedCert(lanIPs);
    httpsServer = createHttpsServer({ key, cert }, (req, res) => handleRequest(req, res, true));
  } catch (error) {
    console.error('  ⚠️  Не удалось поднять HTTPS для телефона (нужен системный openssl):', error.message);
  }
}

httpServer.listen(PORT, () => {
  console.log(`\n  ☎️  Телефонная книга готова: Маквин, Мэтр, Док Хадсон`);
  console.log(`      На этом компьютере:  http://localhost:${PORT}`);
  console.log('');
  console.log(
    ANTHROPIC_API_KEY
      ? '  ✅ мозги: Claude (настоящий диалог, максимум качества)'
      : GROQ_API_KEY
      ? `  ⚡ мозги: Groq, ${GROQ_MODEL} (настоящий диалог, быстро — доли секунды)`
      : NVIDIA_API_KEY
      ? `  🐢 мозги: NVIDIA NIM, ${NVIDIA_MODEL} (настоящий диалог, но медленно — 11-18с на бесплатном тарифе)`
      : '  ⚙️  мозги: локальный движок фраз (задай GROQ_API_KEY — бесплатно и быстро — на console.groq.com)'
  );
  console.log(FISH_API_KEY ? '  ✅ голос: Fish Audio' : '  ⚠️  голос: FISH_API_KEY не задан — будет робот-голос браузера');
  console.log('');
});

if (httpsServer) {
  httpsServer.listen(HTTPS_PORT, () => {
    if (lanIPs.length) {
      console.log('  📱 С телефона (тот же Wi-Fi):');
      for (const ip of lanIPs) console.log(`      https://${ip}:${HTTPS_PORT}`);
      console.log('      (браузер один раз спросит про небезопасное соединение — это нормально)');
    } else {
      console.log('  ⚠️  Не нашёл IP в локальной сети — телефон не сможет подключиться. Проверь Wi-Fi.');
    }
    console.log('');
  });
}
