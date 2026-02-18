'use strict'

const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const {Cam} = require('onvif')
const {fetch} = require('undici')

const app = express()
app.set('trust proxy', 1)
app.use(express.json({limit: '2mb'}))

app.use((req, res, next) => {
  const start = Date.now()
  console.log(
    `[REQ] ${req.method} ${req.originalUrl} origin=${req.headers.origin || '-'} ct=${req.headers['content-type'] || '-'}`
  )

  res.on('finish', () => {
    console.log(
      `[RES] ${req.method} ${req.originalUrl} -> ${res.statusCode} ${Date.now() - start}ms`
    )
  })

  next()
})

/* ──────────────────────────────────────────────
 * CORS (semplice)
 * ────────────────────────────────────────────── */
const allowOrigins = process.env.CONTROL_API_ALLOW_ORIGINS || '*'
app.use(
  cors({
    origin: allowOrigins === '*' ? true : allowOrigins.split(',').map(s => s.trim()),
    credentials: true,
  })
)

app.use((req, res, next) => {
  res.setHeader('X-WebcamGo-Control-Api', '1')
  next()
})

/* ──────────────────────────────────────────────
 * API KEY middleware
 * - consuma header: x-api-key
 * - lascia libero /v1/health
 * ────────────────────────────────────────────── */
function requireApiKey(req, res, next) {
  // lascia passare i preflight CORS
  if (req.method === 'OPTIONS') return next()

  // health libero
  if (req.path === '/v1/health') return next()

  const required = (process.env.CONTROL_API_KEY || '').trim()
  if (!required) return next()

  const provided = (req.header('x-api-key') || '').trim()
  if (!provided || provided !== required) {
    return res.status(401).json({ok: false, error: 'unauthorized'})
  }
  next()
}

app.use(requireApiKey)

/* ──────────────────────────────────────────────
 * Utils
 * ────────────────────────────────────────────── */
const sleep = ms => new Promise(r => setTimeout(r, ms))

function withTimeout(ms, fn) {
  const controller = new AbortController()
  const t = setTimeout(() => controller.abort(new Error('timeout')), ms)
  return fn(controller.signal).finally(() => clearTimeout(t))
}

function normalizeBaseUrl(baseUrl, port) {
  // baseUrl può arrivare come:
  // - "172.29.0.10"
  // - "http://172.29.0.10"
  // - "http://172.29.0.10:80"
  const hasProto = /^https?:\/\//i.test(baseUrl)
  const url = new URL(hasProto ? baseUrl : `http://${baseUrl}`)
  if (port) url.port = String(port)
  return url.toString().replace(/\/+$/, '')
}

function toBasicAuthHeader(user, pass) {
  return 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64')
}

function looksLikeDigestChallenge(wwwAuth) {
  return typeof wwwAuth === 'string' && /^digest/i.test(wwwAuth.trim())
}

function parseDigestChallenge(header) {
  // Esempio: Digest realm="...", nonce="...", qop="auth", opaque="..."
  const params = Object.fromEntries(
    [...header.matchAll(/(\w+)=("([^"]+)"|([^,]+))/g)].map(([_, k, __, qval, val]) => [
      k.toLowerCase(),
      qval || val,
    ])
  )
  return params
}

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex')
}

function buildDigestAuthHeader({method, url, user, pass, challenge, nc = '00000001'}) {
  const u = new URL(url)
  const uri = u.pathname + (u.search || '')
  const realm = challenge.realm || ''
  const nonce = challenge.nonce || ''
  const qopRaw = challenge.qop || ''
  const qop = /\bauth\b/i.test(qopRaw) ? 'auth' : qopRaw.split(',')[0] || null
  const algorithm = (challenge.algorithm || 'MD5').toUpperCase()
  const opaque = challenge.opaque

  if (algorithm !== 'MD5') {
    // per ora supportiamo MD5 (quasi tutte le cam fanno così)
    // se capiterà MD5-sess, si estende.
  }

  const ha1 = md5(`${user}:${realm}:${pass}`)
  const ha2 = md5(`${method.toUpperCase()}:${uri}`)

  let response
  let extra = ''
  const cnonce = crypto.randomBytes(8).toString('hex')

  if (qop) {
    response = md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    extra = `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`
  } else {
    response = md5(`${ha1}:${nonce}:${ha2}`)
  }

  const opaquePart = opaque ? `, opaque="${opaque}"` : ''
  return (
    `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", ` +
    `response="${response}", algorithm=${algorithm}` +
    extra +
    opaquePart
  )
}

async function fetchWithBasicOrDigest(
  url,
  {method = 'GET', user, pass, headers = {}, body, timeoutMs = 8000} = {}
) {
  // 1) prova preemptive Basic (molte cam accettano)
  // 2) se 401 con Digest challenge -> retry Digest
  // 3) se 401 con Basic challenge -> retry Basic (non-preemptive ma uguale)
  return withTimeout(timeoutMs, async signal => {
    const commonHeaders = {
      'User-Agent': 'webcamgo-control-api',
      ...headers,
    }

    // Tentativo 1: Basic preemptive
    let r = await fetch(url, {
      method,
      signal,
      headers: {
        ...commonHeaders,
        ...(user && pass ? {Authorization: toBasicAuthHeader(user, pass)} : {}),
      },
      body,
    })

    if (r.status !== 401) return r

    const wwwAuth = r.headers.get('www-authenticate') || ''
    if (looksLikeDigestChallenge(wwwAuth) && user && pass) {
      const challenge = parseDigestChallenge(wwwAuth)
      const auth = buildDigestAuthHeader({method, url, user, pass, challenge})
      r = await fetch(url, {
        method,
        signal,
        headers: {...commonHeaders, Authorization: auth},
        body,
      })
      return r
    }

    // fallback: se basic richiesto
    if (/^basic/i.test(wwwAuth) && user && pass) {
      r = await fetch(url, {
        method,
        signal,
        headers: {...commonHeaders, Authorization: toBasicAuthHeader(user, pass)},
        body,
      })
      return r
    }

    return r
  })
}

async function connectOnvif({ip, port = 80, user, pass, timeoutMs = 9000}) {
  return withTimeout(timeoutMs, async () => {
    return new Promise((resolve, reject) => {
      new Cam(
        {
          hostname: ip,
          port: parseInt(port, 10),
          username: user,
          password: pass,
        },
        function (err) {
          if (err) return reject(err)
          resolve(this)
        }
      )
    })
  })
}

async function getFirstProfileToken(cam) {
  const profiles = await new Promise((resolve, reject) =>
    cam.getProfiles((err, result) => (err ? reject(err) : resolve(result)))
  )
  const token = profiles?.[0]?.$?.token || profiles?.[0]?.token
  if (!token) throw new Error('ProfileToken assente')
  return token
}

function normalizeOnvifPresets(raw) {
  if (!raw) return []

  // Caso 1: array di preset “classici”
  if (Array.isArray(raw)) {
    return raw
      .map((p, i) => {
        const token = p?.$?.token || p?.token || p?.PresetToken || p?.presetToken || String(i + 1)
        const name = p?.Name || p?.name || p?.$?.Name || p?.$?.name || null
        return {token: String(token), name: name ? String(name) : null}
      })
      .filter(p => p.token)
  }

  // Caso 2: oggetto { token: "Nome" } oppure { token: {name:"Nome"} }
  if (raw && typeof raw === 'object') {
    return Object.entries(raw)
      .map(([token, val]) => ({
        token: String(token),
        name: typeof val === 'string' ? val : (val?.name ?? val?.Name ?? `Preset ${token}`),
      }))
      .filter(p => p.token)
  }

  return []
}

function extractDahuaPowerUpPresetId(text) {
  const s = String(text || '')
  const m = s.match(/table\.PowerUp\[0\]\.PresetId\s*=\s*([0-9]+)/i)
  return m && m[1] ? m[1] : null
}

async function getDahuaPowerUpPresetId(base, {user, pass}) {
  const url = `${base}/cgi-bin/configManager.cgi?action=getConfig&name=PowerUp`
  const r = await fetchWithBasicOrDigest(url, {user, pass, timeoutMs: 8000})
  const text = await r.text().catch(() => '')

  if (!r.ok) return {ok: false, status: r.status, text: text.slice(0, 500)}

  const presetId = extractDahuaPowerUpPresetId(text)
  if (!presetId) return {ok: false, status: 200, text: text.slice(0, 500)}

  return {ok: true, presetId}
}

// ✅ parse risposta Dahua: righe "table.Encode[0].MainFormat[0].Video.X=Y"
function parseKeyValueBody(bodyText = '') {
  const out = {}
  String(bodyText)
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .forEach(line => {
      const idx = line.indexOf('=')
      if (idx <= 0) return
      const k = line.slice(0, idx).trim()
      const v = line.slice(idx + 1).trim()
      out[k] = v
    })
  return out
}

// ✅ estrae i campi che ti interessano dal Main stream
function pickDahuaMainVideo(cfg) {
  // MainFormat[0] = Main Stream in tantissime Dahua (è quello che ti serve per la tua schermata)
  const base = 'table.Encode[0].MainFormat[0].Video.'

  const compression = cfg[base + 'Compression'] || null // H.264 / H.265
  const resolution = cfg[base + 'resolution'] || null // es "1920x1080"
  const fps = cfg[base + 'FPS'] ? Number(cfg[base + 'FPS']) : null
  const bitrateCtrl = cfg[base + 'BitRateControl'] || null // CBR / VBR
  const bitrate = cfg[base + 'BitRate'] ? Number(cfg[base + 'BitRate']) : null
  const gop = cfg[base + 'GOP'] ? Number(cfg[base + 'GOP']) : null // spesso equivale a I-Frame interval

  // width/height (se presenti)
  const width = cfg[base + 'Width'] ? Number(cfg[base + 'Width']) : null
  const height = cfg[base + 'Height'] ? Number(cfg[base + 'Height']) : null

  return {
    encoding: compression,
    bitrate_type: bitrateCtrl,
    bitrate_kbps: bitrate,
    fps,
    gop,
    resolution:
      width && height
        ? {width, height}
        : resolution
          ? (() => {
              const [w, h] = resolution.split('x').map(n => Number(n))
              return w && h ? {width: w, height: h} : {width: null, height: null}
            })()
          : {width: null, height: null},
    raw: cfg,
  }
}

async function digestGetText(url, user, pass, {timeoutMs = 8000, headers = {}} = {}) {
  const r = await fetchWithBasicOrDigest(url, {
    method: 'GET',
    user,
    pass,
    timeoutMs,
    headers: {Accept: 'text/plain,*/*', ...headers},
  })

  const text = await r.text().catch(() => '')
  if (!r.ok) {
    const err = new Error(text?.slice(0, 200) || `HTTP ${r.status}`)
    err.status = r.status
    err.body = text
    throw err
  }
  return text
}

app.get('/v1/health', (req, res) => {
  res.json({ok: true, service: 'webcamgo-control-api'})
})

app.get('/onvif', async (req, res) => {
  const {ip, user, pass, port: port = 80} = req.query
  if (!ip || !user || !pass) {
    return res.status(400).json({
      success: false,
      error: 'Parametri richiesti: ip, user, pass',
      error_type: 'bad_request',
    })
  }

  try {
    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 10000,
    })

    const out = {
      success: true,
      ip_address: String(ip),
      uri: `http://${ip}:${port}/onvif/device_service`,
      errors: {},
    }

    // Device information
    try {
      const info = await new Promise((ok, ko) =>
        cam.getDeviceInformation((e, i) => (e ? ko(e) : ok(i)))
      )
      Object.assign(out, {
        model_number: info?.Model ?? info?.model ?? null,
        firmware_version: info?.FirmwareVersion ?? info?.firmwareVersion ?? null,
        serial_number: info?.SerialNumber ?? info?.serialNumber ?? null,
        manufacturer: info?.Manufacturer ?? info?.manufacturer ?? null,
        hardware: info?.HardwareId ?? info?.hardwareId ?? null,
      })
    } catch (e) {
      out.errors.device_info = e?.message || String(e)
    }

    // Capabilities / ONVIF version / PTZ supported
    try {
      const caps = await new Promise((ok, ko) => cam.getCapabilities((e, d) => (e ? ko(e) : ok(d))))

      out.ptz_supported = Boolean(caps?.PTZ?.XAddr)
      out.services = Object.keys(cam.services || {})

      const supported = caps?.device?.system?.supportedVersions
      const versionFromSupported =
        Array.isArray(supported) && supported.length > 0
          ? `${supported.at(-1).major}.${supported.at(-1).minor}`
          : null

      const versionFromNamespace = caps?.media?.Namespace?.match(/ver=(\d+\.\d+)/)?.[1]
      out.onvif_version = versionFromSupported || versionFromNamespace || null
    } catch (e) {
      out.errors.onvif_version = 'getCapabilities: ' + (e?.message || String(e))
    }

    // PTZ controls + zoom
    try {
      const profiles = await new Promise((resolve, reject) =>
        cam.getProfiles((err, result) => (err ? reject(err) : resolve(result)))
      )

      const ptzConfigs = (profiles || []).map(p => ({
        zoomPresent: !!p?.PTZConfiguration?.ZoomLimits,
        panTiltPresent: !!p?.PTZConfiguration?.PanTiltLimits,
      }))

      out.ptz_zoom = ptzConfigs.some(p => p.zoomPresent)
      out.ptz_controls = ptzConfigs.some(p => p.panTiltPresent)
    } catch (e) {
      out.errors.ptz_profile = 'getProfiles: ' + (e?.message || String(e))
      out.ptz_controls = false
      out.ptz_zoom = false
    }

    // services list (best effort)
    try {
      out.services = cam.services ? Object.keys(cam.services) : []
    } catch (e) {
      out.errors.services = e?.message || String(e)
    }

    // RTSP URI (best effort)
    try {
      const r = await new Promise((ok, ko) =>
        cam.getStreamUri({protocol: 'RTSP', profileToken: '000'}, (e, r) => (e ? ko(e) : ok(r)))
      )
      out.rtsp_uri = r?.uri || null
    } catch (e) {
      out.errors.rtsp_uri = e?.message || String(e)
    }

    // System time (best effort)
    try {
      const xml = await new Promise((ok, ko) =>
        cam.getSystemDateAndTime((e, _d, raw) => (e ? ko(e) : ok(raw)))
      )
      out.system_time = xml || null
    } catch (e) {
      out.errors.system_time = e?.message || String(e)
    }

    return res.json(out)
  } catch (err) {
    let error_type = 'unknown'
    if (err?.name === 'AbortError') error_type = 'timeout'
    else if (String(err?.message || '').includes('ENOTFOUND')) error_type = 'dns'
    else if (String(err?.message || '').includes('401')) error_type = 'unauthorized'
    else if (String(err?.message || '').includes('ECONNREFUSED')) error_type = 'unreachable'
    else if (String(err?.message || '').includes('ETIMEDOUT')) error_type = 'timeout'

    return res.json({
      success: false,
      error: err?.message || String(err),
      error_type,
    })
  }
})

app.post('/v1/webcams/:id/reboot', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, brand = '', mode = ''} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const b = String(brand).toLowerCase()
    const m = String(mode).toLowerCase()

    // Hikvision ISAPI reboot (spesso Basic o Digest; qui proviamo Basic preemptive e poi Digest se serve)
    if (m === 'hikvision_isapi' || b.includes('hikvision')) {
      const base = normalizeBaseUrl(String(ip), port)
      const url = `${base}/ISAPI/System/reboot`
      const body = '<SystemReboot><reboot>true</reboot></SystemReboot>'

      const r = await fetchWithBasicOrDigest(url, {
        method: 'PUT',
        user: String(user),
        pass: String(pass),
        timeoutMs: 9000,
        headers: {'Content-Type': 'application/xml', 'Accept': 'application/xml'},
        body,
      })

      if (!r.ok) {
        const text = await r.text().catch(() => '')
        return res
          .status(502)
          .json({ok: false, error: 'reboot_failed', status: r.status, detail: text?.slice(0, 300)})
      }

      return res.json({ok: true, via: 'hikvision_isapi'})
    }

    // Dahua CGI reboot (se serve)
    if (m === 'dahua_cgi') {
      const base = normalizeBaseUrl(String(ip), port)
      const url = `${base}/cgi-bin/magicBox.cgi?action=reboot`

      const r = await fetchWithBasicOrDigest(url, {
        method: 'GET',
        user: String(user),
        pass: String(pass),
        timeoutMs: 9000,
        headers: {Accept: 'text/plain'},
      })

      if (!r.ok) {
        const text = await r.text().catch(() => '')
        return res
          .status(502)
          .json({ok: false, error: 'reboot_failed', status: r.status, detail: text?.slice(0, 300)})
      }

      return res.json({ok: true, via: 'dahua_cgi'})
    }

    // Default: ONVIF systemReboot
    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    await withTimeout(9000, async () => {
      return new Promise((resolve, reject) =>
        cam.systemReboot(err => (err ? reject(err) : resolve()))
      )
    })

    return res.json({ok: true, via: 'onvif'})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'reboot_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/ptz', async (req, res) => {
  try {
    const {
      ip,
      port = 80,
      user,
      pass,
      brand = '',
      mode = '',
      command,
      speed = 0.5,
      durationMs = 200,
      presetToken,
      channel = 1, // per Dahua CGI spesso 1 sui dome
    } = req.body || {}

    if (!ip || !user || !pass || !command) {
      return res.status(400).json({
        ok: false,
        error: 'bad_request',
        message: 'ip,user,pass,command obbligatori',
      })
    }

    const b = String(brand).toLowerCase().trim()
    const m = String(mode).toLowerCase().trim()
    const cmd = String(command).toLowerCase().trim()

    // ── Dahua CGI PTZ (start + stop automatico)
    if (m === 'dahua_cgi' || b.includes('dahua')) {
      const base = normalizeBaseUrl(String(ip), port)

      const dahuaCodeByCommand = {
        left: 'Left',
        right: 'Right',
        up: 'Up',
        down: 'Down',
        zoom_in: 'ZoomTele',
        zoom_out: 'ZoomWide',
        goto_preset: 'GotoPreset',
        goto_home: 'GotoPreset', // usa PresetId letto da PowerUp
      }

      if (cmd === 'stop') {
        // Stop generico: su Dahua si fa chiamando ptz.cgi?action=stop con stesso code
        // Qui usiamo "Left" come placeholder (alcuni firmware lo ignorano e stoppa comunque).
        const stopUrl = `${base}/cgi-bin/ptz.cgi?action=stop&channel=${channel}&code=Left&arg1=0&arg2=0&arg3=0`
        const r = await fetchWithBasicOrDigest(stopUrl, {user, pass, timeoutMs: 7000})
        if (!r.ok) return res.status(500).json({ok: false, error: 'ptz_failed', status: r.status})
        return res.json({ok: true, via: 'dahua_cgi', command: 'stop'})
      }

      const code = dahuaCodeByCommand[cmd]
      if (!code) {
        return res.status(400).json({
          ok: false,
          error: 'bad_request',
          message: 'command non supportato per dahua_cgi',
          debug: {receivedCommand: command, normalized: cmd},
        })
      }

      const sp = Math.max(1, Math.min(8, Math.round(Number(speed) * 8 || 4))) // 1..8
      const isZoom = code === 'ZoomTele' || code === 'ZoomWide'

      let arg1 = 0,
        arg2 = isZoom ? sp : 0,
        arg3 = isZoom ? 0 : sp

      if (cmd === 'goto_home') {
        const cfg = await getDahuaPowerUpPresetId(base, {user, pass})
        if (!cfg.ok) {
          return res.status(502).json({
            ok: false,
            error: 'ptz_failed',
            message: 'impossibile leggere PresetId da Ptz.PtzPowerUp',
            detail: {status: cfg.status, text: cfg.text},
          })
        }

        const presetId = String(cfg.presetId)

        const urlArg2 =
          `${base}/cgi-bin/ptz.cgi?action=start` +
          `&channel=${channel}&code=GotoPreset&arg1=0&arg2=${encodeURIComponent(presetId)}&arg3=0`

        const urlArg3 =
          `${base}/cgi-bin/ptz.cgi?action=start` +
          `&channel=${channel}&code=GotoPreset&arg1=0&arg2=0&arg3=${encodeURIComponent(presetId)}`

        const r2 = await fetchWithBasicOrDigest(urlArg2, {user, pass, timeoutMs: 8000})
        if (r2.ok) {
          return res.json({
            ok: true,
            via: 'dahua_cgi',
            command: 'goto_home',
            presetId,
            variant: 'arg2',
          })
        }

        const r3 = await fetchWithBasicOrDigest(urlArg3, {user, pass, timeoutMs: 8000})
        if (r3.ok) {
          return res.json({
            ok: true,
            via: 'dahua_cgi',
            command: 'goto_home',
            presetId,
            variant: 'arg3',
            note: 'fallback (arg2 non accettato dal firmware)',
          })
        }

        const t2 = await r2.text().catch(() => '')
        const t3 = await r3.text().catch(() => '')
        return res.status(502).json({
          ok: false,
          error: 'ptz_failed',
          message: 'GotoPreset fallito anche dopo lettura PresetId',
          detail: {
            presetId,
            arg2: {status: r2.status, text: t2.slice(0, 300)},
            arg3: {status: r3.status, text: t3.slice(0, 300)},
          },
        })
      }

      if (cmd === 'goto_preset') {
        if (presetToken == null) {
          return res
            .status(400)
            .json({ok: false, error: 'bad_request', message: 'presetToken obbligatorio'})
        }

        // Variante A (come non-VPN): preset in arg2
        const urlA =
          `${base}/cgi-bin/ptz.cgi?action=start` +
          `&channel=${channel}&code=GotoPreset&arg1=0&arg2=${encodeURIComponent(String(presetToken))}&arg3=0`

        // Variante B: preset in arg3
        const urlB =
          `${base}/cgi-bin/ptz.cgi?action=start` +
          `&channel=${channel}&code=GotoPreset&arg1=0&arg2=0&arg3=${encodeURIComponent(String(presetToken))}`

        const rA = await fetchWithBasicOrDigest(urlA, {user, pass, timeoutMs: 8000})
        if (rA.ok) {
          return res.json({
            ok: true,
            via: 'dahua_cgi',
            command: 'goto_preset',
            presetToken: String(presetToken),
            variant: 'arg2',
          })
        }

        const rB = await fetchWithBasicOrDigest(urlB, {user, pass, timeoutMs: 8000})
        if (rB.ok) {
          return res.json({
            ok: true,
            via: 'dahua_cgi',
            command: 'goto_preset',
            presetToken: String(presetToken),
            variant: 'arg3',
          })
        }

        const tA = await rA.text().catch(() => '')
        const tB = await rB.text().catch(() => '')
        return res.status(500).json({
          ok: false,
          error: 'ptz_failed',
          detail: {
            arg2: {status: rA.status, text: tA.slice(0, 300)},
            arg3: {status: rB.status, text: tB.slice(0, 300)},
          },
        })
      }

      const startUrl =
        `${base}/cgi-bin/ptz.cgi?action=start` +
        `&channel=${channel}&code=${encodeURIComponent(code)}` +
        `&arg1=${encodeURIComponent(arg1)}&arg2=${encodeURIComponent(arg2)}&arg3=${encodeURIComponent(arg3)}`

      const stopUrl = startUrl.replace('action=start', 'action=stop')

      const r1 = await fetchWithBasicOrDigest(startUrl, {user, pass, timeoutMs: 7000})
      if (!r1.ok) {
        const text = await r1.text().catch(() => '')
        console.log('[PTZ][DAHUA] FAIL', {
          status: r1.status,
          startUrl,
          text: text.slice(0, 300),
        })
        return res
          .status(502)
          .json({ok: false, error: 'ptz_failed', status: r1.status, detail: text?.slice(0, 300)})
      }

      // stop automatico (non per goto_preset, dove spesso non serve)
      if (cmd !== 'goto_preset') {
        setTimeout(
          () => {
            fetchWithBasicOrDigest(stopUrl, {user, pass, timeoutMs: 7000}).catch(() => {})
          },
          Math.max(50, Math.min(2000, Number(durationMs) || 200))
        )
      }

      return res.json({ok: true, via: 'dahua_cgi', command: cmd})
    }

    // ── ONVIF PTZ (relativeMove / stop / gotoPreset)
    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    const profileToken = await getFirstProfileToken(cam)

    if (cmd === 'stop') {
      await new Promise((resolve, reject) =>
        cam.stop({profileToken, panTilt: true, zoom: true}, err => (err ? reject(err) : resolve()))
      )
      return res.json({ok: true, via: 'onvif', command: 'stop'})
    }

    if (cmd === 'goto_preset') {
      if (presetToken == null) {
        return res.status(400).json({
          ok: false,
          error: 'bad_request',
          message: 'presetToken obbligatorio per goto_preset',
        })
      }
      await new Promise((resolve, reject) =>
        cam.gotoPreset({profileToken, presetToken: String(presetToken)}, err =>
          err ? reject(err) : resolve()
        )
      )
      return res.json({
        ok: true,
        via: 'onvif',
        command: 'goto_preset',
        presetToken: String(presetToken),
      })
    }

    // relativeMove: translation normalizzata -1..1
    const s = Math.max(0.05, Math.min(1, Number(speed) || 0.5))
    const translation = {}

    if (cmd === 'left') translation.x = -s
    else if (cmd === 'right') translation.x = s
    else if (cmd === 'up') translation.y = s
    else if (cmd === 'down') translation.y = -s
    else if (cmd === 'zoom_in') translation.zoom = s
    else if (cmd === 'zoom_out') translation.zoom = -s
    else {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'command non supportato'})
    }

    await new Promise((resolve, reject) =>
      cam.relativeMove({profileToken, translation}, err => (err ? reject(err) : resolve()))
    )

    // stop automatico
    await sleep(Math.max(50, Math.min(2000, Number(durationMs) || 200)))
    await new Promise((resolve, reject) =>
      cam.stop({profileToken, panTilt: true, zoom: true}, err => (err ? reject(err) : resolve()))
    )

    return res.json({ok: true, via: 'onvif', command: cmd})
  } catch (e) {
    return res.status(500).json({ok: false, error: 'ptz_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/cgi', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, path} = req.body || {}
    if (!ip || !user || !pass || !path) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass,path obbligatori'})
    }

    const p = String(path)
    // allowlist minima: solo /cgi-bin/
    if (!p.startsWith('/cgi-bin/')) {
      return res.status(400).json({ok: false, error: 'bad_request', message: 'path non consentito'})
    }

    const base = normalizeBaseUrl(String(ip), port)
    const url = `${base}${p}`

    const r = await fetchWithBasicOrDigest(url, {
      method: 'GET',
      user: String(user),
      pass: String(pass),
      timeoutMs: 8000,
    })
    const text = await r.text().catch(() => '')

    if (!r.ok) {
      return res
        .status(502)
        .json({ok: false, error: 'cgi_failed', status: r.status, detail: text?.slice(0, 300)})
    }

    return res.json({ok: true, raw: text})
  } catch (e) {
    return res.status(500).json({ok: false, error: 'cgi_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/ptz/status', async (req, res) => {
  try {
    const {ip, port = 80, user, pass} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    const profileToken = await getFirstProfileToken(cam)

    const status = await new Promise((resolve, reject) =>
      cam.getStatus({profileToken}, (err, result) => (err ? reject(err) : resolve(result)))
    )

    const zoom =
      status?.position?.zoom?.x ?? status?.position?.Zoom?.x ?? status?.zoom ?? status?.Zoom ?? null

    return res.json({
      ok: true,
      zoom: typeof zoom === 'number' ? zoom : null,
      raw: status || null,
    })
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'ptz_status_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/ptz/relative', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, pan = 0, tilt = 0, zoom = 0} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    const profileToken = await getFirstProfileToken(cam)

    const translation = {
      x: Number(pan) || 0,
      y: Number(tilt) || 0,
      zoom: Number(zoom) || 0,
    }

    await new Promise((resolve, reject) =>
      cam.relativeMove({profileToken, translation}, err => (err ? reject(err) : resolve()))
    )

    return res.json({ok: true})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'ptz_relative_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/ptz/stop', async (req, res) => {
  try {
    const {ip, port = 80, user, pass} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    const profileToken = await getFirstProfileToken(cam)

    await new Promise((resolve, reject) =>
      cam.stop({profileToken, panTilt: true, zoom: true}, err => (err ? reject(err) : resolve()))
    )

    return res.json({ok: true})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'ptz_stop_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/ptz/absolute', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, zoom} = req.body || {}
    if (!ip || !user || !pass || zoom == null) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass,zoom obbligatori'})
    }

    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    const profileToken = await getFirstProfileToken(cam)

    const z = Math.max(0, Math.min(1, Number(zoom)))

    await new Promise((resolve, reject) =>
      cam.absoluteMove(
        {
          profileToken,
          position: {x: 0, y: 0, zoom: z},
          speed: {x: 0, y: 0, zoom: 1},
        },
        err => (err ? reject(err) : resolve())
      )
    )

    return res.json({ok: true})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'ptz_absolute_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/ptz/dahua', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, action, code, channel = 0, speed = 1} = req.body || {}
    if (!ip || !user || !pass || !action || !code) {
      return res.status(400).json({
        ok: false,
        error: 'bad_request',
        message: 'ip,user,pass,action,code obbligatori',
      })
    }

    const base = normalizeBaseUrl(String(ip), port)

    const isZoom = String(code) === 'ZoomTele' || String(code) === 'ZoomWide'
    const arg1 = 0
    const arg2 = isZoom ? Number(speed) || 1 : 0
    const arg3 = isZoom ? 0 : Number(speed) || 1

    const url =
      `${base}/cgi-bin/ptz.cgi?action=${encodeURIComponent(String(action))}` +
      `&channel=${encodeURIComponent(String(channel))}` +
      `&code=${encodeURIComponent(String(code))}` +
      `&arg1=${encodeURIComponent(String(arg1))}` +
      `&arg2=${encodeURIComponent(String(arg2))}` +
      `&arg3=${encodeURIComponent(String(arg3))}`

    const r = await fetchWithBasicOrDigest(url, {
      method: 'GET',
      user: String(user),
      pass: String(pass),
      timeoutMs: 8000,
    })

    const text = await r.text().catch(() => '')
    if (!r.ok) {
      return res
        .status(502)
        .json({ok: false, error: 'dahua_ptz_failed', status: r.status, detail: text?.slice(0, 300)})
    }

    return res.json({ok: true, raw: text})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'dahua_ptz_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/onvif/presets', async (req, res) => {
  try {
    const {ip, port = 80, user, pass} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })
    const profileToken = await getFirstProfileToken(cam)

    const rawPresets = await new Promise((resolve, reject) =>
      cam.getPresets({profileToken}, (err, result) => (err ? reject(err) : resolve(result)))
    )

    const data = normalizeOnvifPresets(rawPresets)

    return res.json({ok: true, data})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'presets_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/onvif/presets/goto', async (req, res) => {
  try {
    const {
      ip,
      port = 80,
      user,
      pass,
      token,
      brand = '',
      mode = '',
      channel = 1,
      durationMs = 200,
    } = req.body || {}

    if (!ip || !user || !pass || token == null) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass,token obbligatori'})
    }

    const presetToken = String(token)
    const b = String(brand).toLowerCase()
    const m = String(mode).toLowerCase()
    const isDahua = m === 'dahua_cgi' || b.includes('dahua')

    async function gotoPresetDahuaCgi() {
      const base = normalizeBaseUrl(String(ip), port)

      const startUrl =
        `${base}/cgi-bin/ptz.cgi?action=start` +
        `&channel=${encodeURIComponent(String(channel))}` +
        `&code=GotoPreset&arg1=0&arg2=0&arg3=${encodeURIComponent(presetToken)}`

      const stopUrl = startUrl.replace('action=start', 'action=stop')

      const r1 = await fetchWithBasicOrDigest(startUrl, {
        method: 'GET',
        user: String(user),
        pass: String(pass),
        timeoutMs: 8000,
      })

      if (!r1.ok) {
        const text = await r1.text().catch(() => '')
        throw new Error(text?.slice(0, 200) || `HTTP ${r1.status}`)
      }

      setTimeout(
        () => {
          fetchWithBasicOrDigest(stopUrl, {
            method: 'GET',
            user: String(user),
            pass: String(pass),
            timeoutMs: 8000,
          }).catch(() => {})
        },
        Math.max(50, Math.min(2000, Number(durationMs) || 200))
      )
    }

    // Se esplicitamente Dahua CGI: non provare ONVIF
    if (isDahua) {
      await gotoPresetDahuaCgi()
      return res.json({
        ok: true,
        message: 'Preset richiamato',
        via: 'dahua_cgi',
        token: presetToken,
      })
    }

    // Prova ONVIF
    try {
      const cam = await connectOnvif({
        ip: String(ip),
        port: +port,
        user: String(user),
        pass: String(pass),
        timeoutMs: 9000,
      })
      const profileToken = await getFirstProfileToken(cam)

      await new Promise((resolve, reject) =>
        cam.gotoPreset({profileToken, presetToken}, err => (err ? reject(err) : resolve()))
      )

      return res.json({ok: true, message: 'Preset richiamato', via: 'onvif', token: presetToken})
    } catch (e) {
      // Fallback automatico Dahua SOLO se brand/mode lo suggerisce
      if (b.includes('dahua')) {
        await gotoPresetDahuaCgi()
        return res.json({
          ok: true,
          message: 'Preset richiamato',
          via: 'dahua_cgi',
          token: presetToken,
        })
      }
      throw e
    }
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'presets_goto_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/onvif/device-info', async (req, res) => {
  try {
    const {ip, port = 80, user, pass} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const cam = await connectOnvif({
      ip: String(ip),
      port: +port,
      user: String(user),
      pass: String(pass),
      timeoutMs: 9000,
    })

    // Device Information
    const info = await new Promise((resolve, reject) =>
      cam.getDeviceInformation((err, result) => (err ? reject(err) : resolve(result)))
    )

    // ONVIF version (best-effort): GetServices(true) se disponibile
    let onvifVersion = null
    try {
      const services = await new Promise((resolve, reject) =>
        cam.getServices({includeCapability: true}, (err, result) =>
          err ? reject(err) : resolve(result)
        )
      )

      // alcuni device ritornano "Version" con Major/Minor
      const devMgmt = (services || []).find(s => {
        const ns = (s?.Namespace || s?.namespace || '').toString().toLowerCase()
        return ns.includes('device/wsdl') || ns.includes('devicemgmt')
      })
      const v = devMgmt?.Version || devMgmt?.version
      if (v && (v?.Major != null || v?.Minor != null)) {
        onvifVersion = `${v.Major ?? v.major}.${v.Minor ?? v.minor}`
      }
    } catch (_) {
      // ok: non tutte le cam supportano bene getServices
    }

    return res.json({
      ok: true,
      model_number: info?.Model ?? info?.model ?? null,
      firmware_version: info?.FirmwareVersion ?? info?.firmwareVersion ?? null,
      serial_number: info?.SerialNumber ?? info?.serialNumber ?? null,
      onvif_version: onvifVersion,
      raw: info || null,
    })
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: 'onvif_device_info_error',
      message: e?.message || String(e),
    })
  }
})

/* ──────────────────────────────────────────────
 * SNAPSHOT (realtime)
 * ────────────────────────────────────────────── */
app.get('/v1/webcams/:id/snapshot', async (req, res) => {
  try {
    const {url, ip, port, user, pass} = req.query

    // Se arriva un URL esplicito, usiamo quello
    let snapshotUrl = url ? String(url) : null

    // Altrimenti proviamo ONVIF per ottenere snapshotUri
    if (!snapshotUrl) {
      if (!ip || !user || !pass) {
        return res.status(400).json({
          ok: false,
          error: 'bad_request',
          message: 'Richiesti: url oppure (ip,user,pass).',
        })
      }

      const cam = await connectOnvif({
        ip: String(ip),
        port: port ? +port : 80,
        user: String(user),
        pass: String(pass),
      })
      const uri = await new Promise((resolve, reject) =>
        cam.getSnapshotUri((err, data) =>
          err ? reject(err) : resolve(data?.uri || data?.Uri || null)
        )
      )
      if (!uri) throw new Error('URI snapshot non ricevuta via ONVIF')
      snapshotUrl = String(uri)
    }

    // Cache-buster per “realtime”
    const u = new URL(/^https?:\/\//i.test(snapshotUrl) ? snapshotUrl : `http://${snapshotUrl}`)
    u.searchParams.set('_ts', Date.now().toString())
    const cacheBusted = u.toString()

    const r = await fetchWithBasicOrDigest(cacheBusted, {
      method: 'GET',
      user: user ? String(user) : undefined,
      pass: pass ? String(pass) : undefined,
      timeoutMs: 10000,
      headers: {
        'Accept': 'image/jpeg',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
      },
    })

    if (!r.ok) {
      const text = await r.text().catch(() => '')
      return res.status(502).json({
        ok: false,
        error: 'snapshot_failed',
        status: r.status,
        detail: text?.slice(0, 300) || r.statusText,
      })
    }

    const ct = r.headers.get('content-type') || ''
    if (!/image\/jpeg/i.test(ct) && !/image\//i.test(ct)) {
      // alcune cam non mettono content-type: proviamo comunque
    }

    res.setHeader('Content-Type', 'image/jpeg')
    res.setHeader('Cache-Control', 'no-store')
    const buf = Buffer.from(await r.arrayBuffer())
    return res.status(200).send(buf)
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: 'snapshot_error',
      message: e?.message || String(e),
    })
  }
})

app.post('/v1/webcams/:id/snapshot/force', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, slug} = req.body || {}
    if (!ip || !user || !pass || !slug) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass,slug obbligatori'})
    }

    const u = new URL(
      `${req.protocol}://${req.get('host')}/v1/webcams/${encodeURIComponent(req.params.id)}/snapshot`
    )
    u.searchParams.set('ip', String(ip))
    u.searchParams.set('port', String(port))
    u.searchParams.set('user', String(user))
    u.searchParams.set('pass', String(pass))
    u.searchParams.set('_ts', Date.now().toString())

    return res.json({ok: true, url: u.toString(), slug: String(slug)})
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'snapshot_force_error', message: e?.message || String(e)})
  }
})

app.get('/v1/leash/:slug', async (req, res) => {
  try {
    const slug = String(req.params.slug || '').trim()
    const datetime = String(req.query.datetime || '').trim()
    const width = String(req.query.width || '').trim()
    const height = String(req.query.height || '').trim()

    if (!slug || !datetime || !width || !height) {
      return res.status(400).json({
        ok: false,
        error: 'bad_request',
        message: 'slug, datetime, width, height obbligatori',
      })
    }

    const token = process.env.LEASH_TOKEN
    if (!token) {
      return res.status(500).json({
        ok: false,
        error: 'misconfig',
        message: 'LEASH_TOKEN mancante',
      })
    }

    const url =
      `https://leash.cloud.webcamgo.com/${encodeURIComponent(slug)}` +
      `?datetime=${encodeURIComponent(datetime)}` +
      `&width=${encodeURIComponent(width)}` +
      `&height=${encodeURIComponent(height)}`

    const r = await fetch(url, {
      headers: {Authorization: `Bearer ${token}`},
    })

    if (!r.ok) {
      const text = await r.text().catch(() => '')
      return res.status(502).json({
        ok: false,
        error: 'upstream_error',
        message: `Leash error HTTP ${r.status}`,
        detail: text.slice(0, 300),
      })
    }

    // leash risponde con image/png
    res.setHeader('Content-Type', r.headers.get('content-type') || 'image/png')
    const buf = Buffer.from(await r.arrayBuffer())
    return res.status(200).send(buf)
  } catch (e) {
    return res.status(500).json({ok: false, error: 'proxy_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/snapshot/force-masked', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, slug} = req.body || {}
    if (!ip || !user || !pass || !slug) {
      return res.status(400).json({
        ok: false,
        error: 'bad_request',
        message: 'ip,user,pass,slug obbligatori',
      })
    }

    // 1) scarica jpeg RAW (stessa logica del tuo /v1/webcams/:id/snapshot)
    const u = new URL(
      `${req.protocol}://${req.get('host')}/v1/webcams/${encodeURIComponent(req.params.id)}/snapshot`
    )
    u.searchParams.set('ip', String(ip))
    u.searchParams.set('port', String(port))
    u.searchParams.set('user', String(user))
    u.searchParams.set('pass', String(pass))
    u.searchParams.set('_ts', Date.now().toString())

    const rawRes = await fetch(u.toString(), {
      headers: {
        // IMPORTANTISSIMO: questo endpoint è interno al control-api, non serve api-key
        'Accept': 'image/jpeg,image/*',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'x-api-key': process.env.CONTROL_API_KEY,
      },
    })

    if (!rawRes.ok) {
      const text = await rawRes.text().catch(() => '')
      return res.status(502).json({
        ok: false,
        error: 'snapshot_failed',
        message: `snapshot http ${rawRes.status}`,
        detail: text.slice(0, 300),
      })
    }

    const rawBuf = Buffer.from(await rawRes.arrayBuffer())
    const imageBase64 = rawBuf.toString('base64')

    // 2) chiama leash /render
    const leashToken = process.env.LEASH_TOKEN
    if (!leashToken) {
      return res.status(500).json({ok: false, error: 'misconfig', message: 'LEASH_TOKEN mancante'})
    }

    const width = 1920
    const height = 1080
    const datetime = new Date().toISOString()

    const leashRes = await fetch(`https://leash.cloud.webcamgo.com/render`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${leashToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        slug,
        datetime,
        width,
        height,
        imageBase64,
      }),
    })

    if (!leashRes.ok) {
      const text = await leashRes.text().catch(() => '')
      return res.status(502).json({
        ok: false,
        error: 'leash_failed',
        message: `Leash error HTTP ${leashRes.status}`,
        detail: text.slice(0, 300),
      })
    }

    res.setHeader('Content-Type', leashRes.headers.get('content-type') || 'image/png')
    const out = Buffer.from(await leashRes.arrayBuffer())
    return res.status(200).send(out)
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'force_masked_error', message: e?.message || String(e)})
  }
})

app.post('/v1/webcams/:id/onvif/media/encoder', async (req, res) => {
  try {
    const {ip, port = 80, user, pass, profileToken} = req.body || {}
    if (!ip || !user || !pass) {
      return res
        .status(400)
        .json({ok: false, error: 'bad_request', message: 'ip,user,pass obbligatori'})
    }

    const cam = await new Promise((resolve, reject) => {
      new Cam(
        {hostname: String(ip), username: String(user), password: String(pass), port: +port},
        function (err) {
          if (err) return reject(err)
          resolve(this)
        }
      )
    })

    const profiles = await new Promise((resolve, reject) =>
      cam.getProfiles((err, result) => (err ? reject(err) : resolve(result)))
    )

    if (!profiles?.length) {
      return res
        .status(500)
        .json({ok: false, error: 'no_profiles', message: 'Nessun profilo ONVIF trovato'})
    }

    const getToken = p => p?.$?.token || p?.token || null

    let p =
      (profileToken && profiles.find(x => String(getToken(x)) === String(profileToken))) ||
      profiles.find(x => x?.VideoEncoderConfiguration) ||
      profiles[0]

    const token = getToken(p)
    const vProfile = p?.VideoEncoderConfiguration || null

    let v = vProfile
    let encoderSource = vProfile ? 'profile.VideoEncoderConfiguration' : null
    let allEncoderConfigs = null

    // 1) fallback: GetVideoEncoderConfigurations
    try {
      if (!v && typeof cam.getVideoEncoderConfigurations === 'function') {
        allEncoderConfigs = await new Promise((resolve, reject) =>
          cam.getVideoEncoderConfigurations((err, result) => (err ? reject(err) : resolve(result)))
        )

        const list = Array.isArray(allEncoderConfigs)
          ? allEncoderConfigs
          : allEncoderConfigs?.VideoEncoderConfigurations ||
            allEncoderConfigs?.videoEncoderConfigurations ||
            []

        function scoreCfg(c, profileName = '') {
          const w = Number(c?.Resolution?.Width ?? null)
          const h = Number(c?.Resolution?.Height ?? null)
          const fps = Number(c?.RateControl?.FrameRateLimit ?? null)
          const br = Number(c?.RateControl?.BitrateLimit ?? null)

          let s = 0
          if (w && h) s += (w * h) / 1000000
          if (fps) s += 5
          if (br) s += 5

          const name = String(profileName || '').toLowerCase()
          if (name.includes('mainstream')) s += w && h ? 10 : 0
          if (name.includes('substream')) s -= w && h ? 5 : 0

          return s
        }

        function pickBestConfig(list, profileName) {
          const arr = Array.isArray(list) ? list : []
          if (!arr.length) return null
          return arr.map(c => ({c, s: scoreCfg(c, profileName)})).sort((a, b) => b.s - a.s)[0].c
        }

        if (Array.isArray(list) && list.length) {
          v = pickBestConfig(list, p?.Name || p?.name || '')
          encoderSource = 'getVideoEncoderConfigurations'
        }
      }
    } catch (_) {}

    // Normalizza ONVIF
    const encoderNormalized = v
      ? {
          encoding: v?.Encoding || v?.encoding || null,
          resolution: {
            width: Number(v?.Resolution?.Width ?? v?.resolution?.width ?? null),
            height: Number(v?.Resolution?.Height ?? v?.resolution?.height ?? null),
          },
          fps: Number(v?.RateControl?.FrameRateLimit ?? v?.rateControl?.frameRateLimit ?? null),
          bitrate_kbps: Number(
            v?.RateControl?.BitrateLimit ?? v?.rateControl?.bitrateLimit ?? null
          ),
          gop: Number(v?.GovLength ?? v?.govLength ?? v?.$?.GovLength ?? v?.$?.govLength ?? null),
          raw: v,
        }
      : null

    const encoderLooksEmpty =
      !encoderNormalized ||
      !(
        encoderNormalized.encoding ||
        encoderNormalized.resolution?.width ||
        encoderNormalized.resolution?.height ||
        encoderNormalized.fps ||
        encoderNormalized.bitrate_kbps ||
        encoderNormalized.gop
      )

    // 2) fallback Dahua solo se ONVIF è vuoto
    let dahua = null
    if (encoderLooksEmpty) {
      try {
        const url = `http://${ip}:${+port}/cgi-bin/configManager.cgi?action=getConfig&name=Encode`
        const text = await digestGetText(url, user, pass)
        const cfg = parseKeyValueBody(text)
        dahua = pickDahuaMainVideo(cfg)
      } catch (_) {}
    }

    const encoderFinal = !encoderLooksEmpty
      ? encoderNormalized
      : dahua
        ? {
            encoding: dahua.encoding,
            resolution: dahua.resolution,
            fps: dahua.fps,
            bitrate_kbps: dahua.bitrate_kbps,
            gop: dahua.gop,
            raw: dahua.raw,
          }
        : null

    const out = {
      ok: true,
      profile: {token, name: p?.Name || p?.name || null},

      encoder_source: !encoderLooksEmpty
        ? encoderSource
        : dahua
          ? 'dahua.configManager.Encode'
          : encoderSource,

      encoder: encoderFinal,

      profiles: profiles.map(x => ({
        token: getToken(x),
        name: x?.Name || x?.name || null,
        hasVideoEncoderConfiguration: !!x?.VideoEncoderConfiguration,
      })),

      encoder_configs: Array.isArray(allEncoderConfigs)
        ? allEncoderConfigs.map(c => ({
            token: c?.$?.token || c?.token || null,
            encoding: c?.Encoding || c?.encoding || null,
            width: Number(c?.Resolution?.Width ?? c?.resolution?.width ?? null),
            height: Number(c?.Resolution?.Height ?? c?.resolution?.height ?? null),
            fps: Number(c?.RateControl?.FrameRateLimit ?? c?.rateControl?.frameRateLimit ?? null),
            bitrate_kbps: Number(
              c?.RateControl?.BitrateLimit ?? c?.rateControl?.bitrateLimit ?? null
            ),
          }))
        : null,

      dahua_encode: dahua || null,
      options: null,
    }

    // options (solo ONVIF)
    try {
      if (typeof cam.getVideoEncoderConfigurationOptions === 'function' && v?.$?.token) {
        const opts = await new Promise((resolve, reject) =>
          cam.getVideoEncoderConfigurationOptions(
            {configurationToken: v.$.token, profileToken: token},
            (err, result) => (err ? reject(err) : resolve(result))
          )
        )
        out.options = opts || null
      }
    } catch (_) {}

    return res.json(out)
  } catch (e) {
    return res
      .status(500)
      .json({ok: false, error: 'onvif_encoder_error', message: e?.message || String(e)})
  }
})

/* ────────────────────────────────────────────── */
process.on('SIGTERM', () => {
  console.log('[PROC] SIGTERM received - shutting down')
})

process.on('SIGINT', () => {
  console.log('[PROC] SIGINT received - shutting down')
})

process.on('uncaughtException', err => {
  console.log('[PROC] uncaughtException', err)
})

process.on('unhandledRejection', err => {
  console.log('[PROC] unhandledRejection', err)
})

const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log('webcamgo-control-api listening on', port)
})
