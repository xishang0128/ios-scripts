const NAME = 'IP4P'
const $ = new Env(NAME)

let arg
if (typeof $argument != 'undefined') {
  arg = Object.fromEntries($argument.split('&').map(item => item.split('=')))
} else {
  arg = {}
}
// $.log(`传入的 $argument: ${$.toStr(arg)}`)

let result = {}
!(async () => {
  if (!isRequest()) {
    throw new Error('不是请求')
  }
  const { url, headers } = $request
  // $.log(`请求 URL: ${url}`)
  // $.log(`请求 headers: ${JSON.stringify(headers, null, 2)}`)

  let [_, protocol, domain, __, path] = url.match(/(^.+?:\/\/)(.+?)(:\d+)?(\/.*?)?$/i)

  const IPv6 = await resolveDomain(domain)
  const { server, port } = parseIP4P(IPv6)
  $persistentStore.write(server,domain+"-ip4")
  result = {
    // url: `${protocol}${server}:${port}${path}`,
    url: `${protocol}${domain}:${port}${path}`,
    headers: Object.fromEntries(
      Object.entries(headers).filter(([key]) => ![':authority', 'host'].includes(key.toLowerCase()))
    ),
  }
})()
  .catch(async e => {
    $.logErr(e)
    $.logErr($.toStr(e))
    const msg = `${$.lodash_get(e, 'message') || $.lodash_get(e, 'error') || e}`
    title = `❌`
    content = msg
    await notify('IP4P', title, content)
    result = {}
  })
  .finally(async () => {
    // $.log(JSON.stringify(result, null, 2))
    $done(result)
  })

// source: https://stackoverflow.com/a/36760050
const IPV4_REGEX = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$/

// source: https://ihateregex.io/expr/ipv6/
const IPV6_REGEX =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/

function isIPv4(ip) {
  return IPV4_REGEX.test(ip)
}

function isIPv6(ip) {
  return IPV6_REGEX.test(ip)
}

async function resolveDomain(domain, opt = {}) {
  const DOMAIN_RESOLVERS = {
    google: async function (domain, type) {
      const resp = await http({
        url: `https://8.8.4.4/resolve`,
        params: {
          name: domain,
          type: type === 'IPv6' ? 'AAAA' : 'A',
        },
        headers: {
          accept: 'application/dns-json',
        },
      })
      const body = JSON.parse(resp.body)
      if (body['Status'] !== 0) {
        throw new Error(`Status is ${body['Status']}`)
      }
      const answers = body['Answer']
      if (answers.length === 0) {
        throw new Error('域名解析无结果')
      }
      return answers[answers.length - 1].data
    },

    cf: async function (domain, type) {
      const resp = await http({
        url: `https://1.0.0.1/dns-query`,
        params: {
          name: domain,
          type: type === 'IPv6' ? 'AAAA' : 'A',
        },
        headers: {
          accept: 'application/dns-json',
        },
      })
      const body = JSON.parse(resp.body)
      if (body['Status'] !== 0) {
        throw new Error(`Status is ${body['Status']}`)
      }
      const answers = body['Answer']
      if (answers.length === 0) {
        throw new Error('域名解析无结果')
      }
      return answers[answers.length - 1].data
    },
    ali: async function (domain, type) {
      const resp = await http({
        url: `http://223.6.6.6/resolve`,
        params: {
          name: domain,
          short: 1,
          type: type === 'IPv6' ? 'AAAA' : 'A',
        },
        headers: {
          accept: 'application/dns-json',
        },
      })
      const answers = JSON.parse(resp.body)
      if (answers.length === 0) {
        throw new Error('域名解析无结果')
      }
      return answers[answers.length - 1]
    },
    tencent: async function (domain, type) {
      const resp = await http({
        url: `http://119.28.28.28/d`,
        params: {
          dn: domain,
          type: type === 'IPv6' ? 'AAAA' : 'A',
        },
        headers: {
          accept: 'application/dns-json',
        },
      })
      const answers = resp.body.split(';').map(i => i.split(',')[0])
      if (answers.length === 0) {
        throw new Error('域名解析无结果')
      }
      return answers[answers.length - 1]
    },
  }
  const ttl = parseFloat(opt.ttl || $.lodash_get(arg, 'TTL') || 60)
  const cache = $.getjson(`${NAME}`, {})

  if (cache && cache[domain] && cache[domain].IPv6 && (Date.now() - cache[domain].timestamp) / 1000 < ttl) {
    return cache[domain].IPv6
  }

  let resolverName = $.lodash_get(arg, 'DNS') || 'ali'

  let resolver = DOMAIN_RESOLVERS[resolverName]

  if (!resolver) {
    resolverName = 'ali'
    resolver = DOMAIN_RESOLVERS[resolverName]
  }
  const msg = `使用 ${resolverName} 解析域名 ${domain}`
  let IPv6
  try {
    IPv6 = await resolver(domain, 'IPv6')
  } catch (e) {
    $.logErr(e)
  }

  if (!isIPv6(IPv6)) {
    throw new Error(`${msg} 解析 IPv6 失败`)
  }
  cache[domain] = {
    IPv6,
    timestamp: Date.now(),
  }
  $.setjson(cache, `${NAME}`)
  return IPv6
}
function parseIP4P(IP4P) {
  let server
  let port
  try {
    if (!/^2001::[^:]+:[^:]+:[^:]+$/.test(IP4P)) {
      throw new Error(`Invalid IP4P: ${IP4P}`)
    }
    let array = IP4P.split(':')

    port = parseInt(array[2], 16)
    let ipab = parseInt(array[3], 16)
    let ipcd = parseInt(array[4], 16)
    let ipa = ipab >> 8
    let ipb = ipab & 0xff
    let ipc = ipcd >> 8
    let ipd = ipcd & 0xff
    server = `${ipa}.${ipb}.${ipc}.${ipd}`
    if (port <= 0 || port > 65535) {
      throw new Error(`Invalid port number: ${port}`)
    }
    if (!isIPv4(server)) {
      throw new Error(`Invalid IP address: ${server}`)
    }
  } catch (e) {
    throw new Error(`IP4P 解析失败: ${e}`)
    // $.logErr(`IP4P 解析失败: ${e}`)
  }
  return { server, port }
}
function isRequest() {
  return typeof $request !== 'undefined'
}
// 请求
async function http(opt = {}) {
  const TIMEOUT = parseFloat(opt.timeout || $.lodash_get(arg, 'TIMEOUT') || 5)
  const RETRIES = parseFloat(opt.retries || $.lodash_get(arg, 'RETRIES') || 1)
  const RETRY_DELAY = parseFloat(opt.retry_delay || $.lodash_get(arg, 'RETRY_DELAY') || 1)

  let timeout = TIMEOUT + 1
  timeout = $.isSurge() ? timeout : timeout * 1000

  let count = 0
  const fn = async () => {
    try {
      if (TIMEOUT) {
        // Surge, Loon, Stash 默认为 5 秒
        return await Promise.race([
          $.http.get({ ...opt, timeout }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('HTTP TIMEOUT')), TIMEOUT * 1000)),
        ])
      }
      return await $.http.get(opt)
    } catch (e) {
      if (count < RETRIES) {
        count++
        $.log(`第 ${count} 次请求失败: ${e.message || e}, 等待 ${RETRY_DELAY}s 后重试`)
        await $.wait(RETRY_DELAY * 1000)
        return await fn()
      }
    }
  }
  return await fn()
}
// 通知
async function notify(title, subt, desc, opts) {
  if ($.lodash_get(arg, 'TYPE') === 'EVENT' || $.lodash_get(arg, 'notify') == 1) {
    $.msg(title, subt, desc, opts)
  } else {
    $.log('🔕', title, subt, desc, opts)
  }
}

// prettier-ignore
function Env(name, opts) {
  class Http {
    constructor(env) {
      this.env = env
    }

    send(opts, method = 'GET') {
      opts = typeof opts === 'string' ? { url: opts } : opts
      let sender = this.get
      if (method === 'POST') {
        sender = this.post
      }
      return new Promise((resolve, reject) => {
        sender.call(this, opts, (err, resp, body) => {
          if (err) reject(err)
          else resolve(resp)
        })
      })
    }

    get(opts) {
      return this.send.call(this.env, opts)
    }

    post(opts) {
      return this.send.call(this.env, opts, 'POST')
    }
  }

  return new (class {
    constructor(name, opts) {
      this.name = name
      this.http = new Http(this)
      this.data = null
      this.dataFile = 'box.dat'
      this.logs = []
      this.isMute = false
      this.isNeedRewrite = false
      this.logSeparator = '\n'
      this.encoding = 'utf-8'
      this.startTime = new Date().getTime()
      Object.assign(this, opts)
      // this.log('', `🔔${this.name}, 开始!`)
    }

    getEnv() {
      if ('undefined' !== typeof $environment && $environment['surge-version'])
        return 'Surge'
      if ('undefined' !== typeof $environment && $environment['stash-version'])
        return 'Stash'
      if ('undefined' !== typeof module && !!module.exports) return 'Node.js'
      if ('undefined' !== typeof $task) return 'Quantumult X'
      if ('undefined' !== typeof $loon) return 'Loon'
      if ('undefined' !== typeof $rocket) return 'Shadowrocket'
    }

    isNode() {
      return 'Node.js' === this.getEnv()
    }

    isQuanX() {
      return 'Quantumult X' === this.getEnv()
    }

    isSurge() {
      return 'Surge' === this.getEnv()
    }

    isLoon() {
      return 'Loon' === this.getEnv()
    }

    isShadowrocket() {
      return 'Shadowrocket' === this.getEnv()
    }

    isStash() {
      return 'Stash' === this.getEnv()
    }

    toObj(str, defaultValue = null) {
      try {
        return JSON.parse(str)
      } catch {
        return defaultValue
      }
    }

    toStr(obj, defaultValue = null) {
      try {
        return JSON.stringify(obj)
      } catch {
        return defaultValue
      }
    }

    getjson(key, defaultValue) {
      let json = defaultValue
      const val = this.getdata(key)
      if (val) {
        try {
          json = JSON.parse(this.getdata(key))
        } catch {}
      }
      return json
    }

    setjson(val, key) {
      try {
        return this.setdata(JSON.stringify(val), key)
      } catch {
        return false
      }
    }

    getScript(url) {
      return new Promise((resolve) => {
        this.get({ url }, (err, resp, body) => resolve(body))
      })
    }

    runScript(script, runOpts) {
      return new Promise((resolve) => {
        let httpapi = this.getdata('@chavy_boxjs_userCfgs.httpapi')
        httpapi = httpapi ? httpapi.replace(/\n/g, '').trim() : httpapi
        let httpapi_timeout = this.getdata(
          '@chavy_boxjs_userCfgs.httpapi_timeout'
        )
        httpapi_timeout = httpapi_timeout ? httpapi_timeout * 1 : 20
        httpapi_timeout =
          runOpts && runOpts.timeout ? runOpts.timeout : httpapi_timeout
        const [key, addr] = httpapi.split('@')
        const opts = {
          url: `http://${addr}/v1/scripting/evaluate`,
          body: {
            script_text: script,
            mock_type: 'cron',
            timeout: httpapi_timeout
          },
          headers: { 'X-Key': key, 'Accept': '*/*' },
          timeout: httpapi_timeout
        }
        this.post(opts, (err, resp, body) => resolve(body))
      }).catch((e) => this.logErr(e))
    }

    loaddata() {
      if (this.isNode()) {
        this.fs = this.fs ? this.fs : require('fs')
        this.path = this.path ? this.path : require('path')
        const curDirDataFilePath = this.path.resolve(this.dataFile)
        const rootDirDataFilePath = this.path.resolve(
          process.cwd(),
          this.dataFile
        )
        const isCurDirDataFile = this.fs.existsSync(curDirDataFilePath)
        const isRootDirDataFile =
          !isCurDirDataFile && this.fs.existsSync(rootDirDataFilePath)
        if (isCurDirDataFile || isRootDirDataFile) {
          const datPath = isCurDirDataFile
            ? curDirDataFilePath
            : rootDirDataFilePath
          try {
            return JSON.parse(this.fs.readFileSync(datPath))
          } catch (e) {
            return {}
          }
        } else return {}
      } else return {}
    }

    writedata() {
      if (this.isNode()) {
        this.fs = this.fs ? this.fs : require('fs')
        this.path = this.path ? this.path : require('path')
        const curDirDataFilePath = this.path.resolve(this.dataFile)
        const rootDirDataFilePath = this.path.resolve(
          process.cwd(),
          this.dataFile
        )
        const isCurDirDataFile = this.fs.existsSync(curDirDataFilePath)
        const isRootDirDataFile =
          !isCurDirDataFile && this.fs.existsSync(rootDirDataFilePath)
        const jsondata = JSON.stringify(this.data)
        if (isCurDirDataFile) {
          this.fs.writeFileSync(curDirDataFilePath, jsondata)
        } else if (isRootDirDataFile) {
          this.fs.writeFileSync(rootDirDataFilePath, jsondata)
        } else {
          this.fs.writeFileSync(curDirDataFilePath, jsondata)
        }
      }
    }

    lodash_get(source, path, defaultValue = undefined) {
      const paths = path.replace(/\[(\d+)\]/g, '.$1').split('.')
      let result = source
      for (const p of paths) {
        result = Object(result)[p]
        if (result === undefined) {
          return defaultValue
        }
      }
      return result
    }

    lodash_set(obj, path, value) {
      if (Object(obj) !== obj) return obj
      if (!Array.isArray(path)) path = path.toString().match(/[^.[\]]+/g) || []
      path
        .slice(0, -1)
        .reduce(
          (a, c, i) =>
            Object(a[c]) === a[c]
              ? a[c]
              : (a[c] = Math.abs(path[i + 1]) >> 0 === +path[i + 1] ? [] : {}),
          obj
        )[path[path.length - 1]] = value
      return obj
    }

    getdata(key) {
      let val = this.getval(key)
      // 如果以 @
      if (/^@/.test(key)) {
        const [, objkey, paths] = /^@(.*?)\.(.*?)$/.exec(key)
        const objval = objkey ? this.getval(objkey) : ''
        if (objval) {
          try {
            const objedval = JSON.parse(objval)
            val = objedval ? this.lodash_get(objedval, paths, '') : val
          } catch (e) {
            val = ''
          }
        }
      }
      return val
    }

    setdata(val, key) {
      let issuc = false
      if (/^@/.test(key)) {
        const [, objkey, paths] = /^@(.*?)\.(.*?)$/.exec(key)
        const objdat = this.getval(objkey)
        const objval = objkey
          ? objdat === 'null'
            ? null
            : objdat || '{}'
          : '{}'
        try {
          const objedval = JSON.parse(objval)
          this.lodash_set(objedval, paths, val)
          issuc = this.setval(JSON.stringify(objedval), objkey)
        } catch (e) {
          const objedval = {}
          this.lodash_set(objedval, paths, val)
          issuc = this.setval(JSON.stringify(objedval), objkey)
        }
      } else {
        issuc = this.setval(val, key)
      }
      return issuc
    }

    getval(key) {
      switch (this.getEnv()) {
        case 'Surge':
        case 'Loon':
        case 'Stash':
        case 'Shadowrocket':
          return $persistentStore.read(key)
        case 'Quantumult X':
          return $prefs.valueForKey(key)
        case 'Node.js':
          this.data = this.loaddata()
          return this.data[key]
        default:
          return (this.data && this.data[key]) || null
      }
    }

    setval(val, key) {
      switch (this.getEnv()) {
        case 'Surge':
        case 'Loon':
        case 'Stash':
        case 'Shadowrocket':
          return $persistentStore.write(val, key)
        case 'Quantumult X':
          return $prefs.setValueForKey(val, key)
        case 'Node.js':
          this.data = this.loaddata()
          this.data[key] = val
          this.writedata()
          return true
        default:
          return (this.data && this.data[key]) || null
      }
    }

    initGotEnv(opts) {
      this.got = this.got ? this.got : require('got')
      this.cktough = this.cktough ? this.cktough : require('tough-cookie')
      this.ckjar = this.ckjar ? this.ckjar : new this.cktough.CookieJar()
      if (opts) {
        opts.headers = opts.headers ? opts.headers : {}
        if (undefined === opts.headers.Cookie && undefined === opts.cookieJar) {
          opts.cookieJar = this.ckjar
        }
      }
    }

    get(request, callback = () => {}) {
      if (request.headers) {
        delete request.headers['Content-Type']
        delete request.headers['Content-Length']

        // HTTP/2 全是小写
        delete request.headers['content-type']
        delete request.headers['content-length']
      }
      if (request.params) {
        request.url += '?' + this.queryStr(request.params)
      }
      // followRedirect 禁止重定向
      if (typeof request.followRedirect !== 'undefined' && !request['followRedirect']) {
        if (this.isSurge() || this.isLoon()) request['auto-redirect'] = false  // Surge & Loon
        if (this.isQuanX()) request.opts ? request['opts']['redirection'] = false : request.opts = { redirection: false }  // Quantumult X
      }
      switch (this.getEnv()) {
        case 'Surge':
        case 'Loon':
        case 'Stash':
        case 'Shadowrocket':
        default:
          if (this.isSurge() && this.isNeedRewrite) {
            request.headers = request.headers || {}
            Object.assign(request.headers, { 'X-Surge-Skip-Scripting': false })
          }
          $httpClient.get(request, (err, resp, body) => {
            if (!err && resp) {
              resp.body = body
              resp.statusCode = resp.status ? resp.status : resp.statusCode
              resp.status = resp.statusCode
            }
            callback(err, resp, body)
          })
          break
        case 'Quantumult X':
          if (this.isNeedRewrite) {
            request.opts = request.opts || {}
            Object.assign(request.opts, { hints: false })
          }
          $task.fetch(request).then(
            (resp) => {
              const {
                statusCode: status,
                statusCode,
                headers,
                body,
                bodyBytes
              } = resp
              callback(
                null,
                { status, statusCode, headers, body, bodyBytes },
                body,
                bodyBytes
              )
            },
            (err) => callback((err && err.error) || 'UndefinedError')
          )
          break
        case 'Node.js':
          let iconv = require('iconv-lite')
          this.initGotEnv(request)
          this.got(request)
            .on('redirect', (resp, nextOpts) => {
              try {
                if (resp.headers['set-cookie']) {
                  const ck = resp.headers['set-cookie']
                    .map(this.cktough.Cookie.parse)
                    .toString()
                  if (ck) {
                    this.ckjar.setCookieSync(ck, null)
                  }
                  nextOpts.cookieJar = this.ckjar
                }
              } catch (e) {
                this.logErr(e)
              }
              // this.ckjar.setCookieSync(resp.headers['set-cookie'].map(Cookie.parse).toString())
            })
            .then(
              (resp) => {
                const {
                  statusCode: status,
                  statusCode,
                  headers,
                  rawBody
                } = resp
                const body = iconv.decode(rawBody, this.encoding)
                callback(
                  null,
                  { status, statusCode, headers, rawBody, body },
                  body
                )
              },
              (err) => {
                const { message: error, response: resp } = err
                callback(
                  error,
                  resp,
                  resp && iconv.decode(resp.rawBody, this.encoding)
                )
              }
            )
          break
      }
    }

    post(request, callback = () => {}) {
      const method = request.method
        ? request.method.toLocaleLowerCase()
        : 'post'

      // 如果指定了请求体, 但没指定 `Content-Type`、`content-type`, 则自动生成。
      if (
        request.body &&
        request.headers &&
        !request.headers['Content-Type'] &&
        !request.headers['content-type']
      ) {
        // HTTP/1、HTTP/2 都支持小写 headers
        request.headers['content-type'] = 'application/x-www-form-urlencoded'
      }
      // 为避免指定错误 `content-length` 这里删除该属性，由工具端 (HttpClient) 负责重新计算并赋值
      if (request.headers) {
        delete request.headers['Content-Length']
        delete request.headers['content-length']
      }
      // followRedirect 禁止重定向
      if (typeof request.followRedirect !== 'undefined' && !request['followRedirect']) {
        if (this.isSurge() || this.isLoon()) request['auto-redirect'] = false  // Surge & Loon
        if (this.isQuanX()) request.opts ? request['opts']['redirection'] = false : request.opts = { redirection: false }  // Quantumult X
      }
      switch (this.getEnv()) {
        case 'Surge':
        case 'Loon':
        case 'Stash':
        case 'Shadowrocket':
        default:
          if (this.isSurge() && this.isNeedRewrite) {
            request.headers = request.headers || {}
            Object.assign(request.headers, { 'X-Surge-Skip-Scripting': false })
          }
          $httpClient[method](request, (err, resp, body) => {
            if (!err && resp) {
              resp.body = body
              resp.statusCode = resp.status ? resp.status : resp.statusCode
              resp.status = resp.statusCode
            }
            callback(err, resp, body)
          })
          break
        case 'Quantumult X':
          request.method = method
          if (this.isNeedRewrite) {
            request.opts = request.opts || {}
            Object.assign(request.opts, { hints: false })
          }
          $task.fetch(request).then(
            (resp) => {
              const {
                statusCode: status,
                statusCode,
                headers,
                body,
                bodyBytes
              } = resp
              callback(
                null,
                { status, statusCode, headers, body, bodyBytes },
                body,
                bodyBytes
              )
            },
            (err) => callback((err && err.error) || 'UndefinedError')
          )
          break
        case 'Node.js':
          let iconv = require('iconv-lite')
          this.initGotEnv(request)
          const { url, ..._request } = request
          this.got[method](url, _request).then(
            (resp) => {
              const { statusCode: status, statusCode, headers, rawBody } = resp
              const body = iconv.decode(rawBody, this.encoding)
              callback(
                null,
                { status, statusCode, headers, rawBody, body },
                body
              )
            },
            (err) => {
              const { message: error, response: resp } = err
              callback(
                error,
                resp,
                resp && iconv.decode(resp.rawBody, this.encoding)
              )
            }
          )
          break
      }
    }
    /**
     *
     * 示例:$.time('yyyy-MM-dd qq HH:mm:ss.S')
     *    :$.time('yyyyMMddHHmmssS')
     *    y:年 M:月 d:日 q:季 H:时 m:分 s:秒 S:毫秒
     *    其中y可选0-4位占位符、S可选0-1位占位符，其余可选0-2位占位符
     * @param {string} fmt 格式化参数
     * @param {number} 可选: 根据指定时间戳返回格式化日期
     *
     */
    time(fmt, ts = null) {
      const date = ts ? new Date(ts) : new Date()
      let o = {
        'M+': date.getMonth() + 1,
        'd+': date.getDate(),
        'H+': date.getHours(),
        'm+': date.getMinutes(),
        's+': date.getSeconds(),
        'q+': Math.floor((date.getMonth() + 3) / 3),
        'S': date.getMilliseconds()
      }
      if (/(y+)/.test(fmt))
        fmt = fmt.replace(
          RegExp.$1,
          (date.getFullYear() + '').substr(4 - RegExp.$1.length)
        )
      for (let k in o)
        if (new RegExp('(' + k + ')').test(fmt))
          fmt = fmt.replace(
            RegExp.$1,
            RegExp.$1.length == 1
              ? o[k]
              : ('00' + o[k]).substr(('' + o[k]).length)
          )
      return fmt
    }

    /**
     *
     * @param {Object} options
     * @returns {String} 将 Object 对象 转换成 queryStr: key=val&name=senku
     */
    queryStr(options) {
      let queryString = ''

      for (const key in options) {
        let value = options[key]
        if (value != null && value !== '') {
          if (typeof value === 'object') {
            value = JSON.stringify(value)
          }
          queryString += `${key}=${value}&`
        }
      }
      queryString = queryString.substring(0, queryString.length - 1)

      return queryString
    }

    /**
     * 系统通知
     *
     * > 通知参数: 同时支持 QuanX 和 Loon 两种格式, EnvJs根据运行环境自动转换, Surge 环境不支持多媒体通知
     *
     * 示例:
     * $.msg(title, subt, desc, 'twitter://')
     * $.msg(title, subt, desc, { 'open-url': 'twitter://', 'media-url': 'https://github.githubassets.com/images/modules/open_graph/github-mark.png' })
     * $.msg(title, subt, desc, { 'open-url': 'https://bing.com', 'media-url': 'https://github.githubassets.com/images/modules/open_graph/github-mark.png' })
     *
     * @param {*} title 标题
     * @param {*} subt 副标题
     * @param {*} desc 通知详情
     * @param {*} opts 通知参数
     *
     */
    msg(title = name, subt = '', desc = '', opts) {
      const toEnvOpts = (rawopts) => {
        switch (typeof rawopts) {
          case undefined:
            return rawopts
          case 'string':
            switch (this.getEnv()) {
              case 'Surge':
              case 'Stash':
              default:
                return { url: rawopts }
              case 'Loon':
              case 'Shadowrocket':
                return rawopts
              case 'Quantumult X':
                return { 'open-url': rawopts }
              case 'Node.js':
                return undefined
            }
          case 'object':
            switch (this.getEnv()) {
              case 'Surge':
              case 'Stash':
              case 'Shadowrocket':
              default: {
                let openUrl =
                  rawopts.url || rawopts.openUrl || rawopts['open-url']
                return { url: openUrl }
              }
              case 'Loon': {
                let openUrl =
                  rawopts.openUrl || rawopts.url || rawopts['open-url']
                let mediaUrl = rawopts.mediaUrl || rawopts['media-url']
                return { openUrl, mediaUrl }
              }
              case 'Quantumult X': {
                let openUrl =
                  rawopts['open-url'] || rawopts.url || rawopts.openUrl
                let mediaUrl = rawopts['media-url'] || rawopts.mediaUrl
                let updatePasteboard =
                  rawopts['update-pasteboard'] || rawopts.updatePasteboard
                return {
                  'open-url': openUrl,
                  'media-url': mediaUrl,
                  'update-pasteboard': updatePasteboard
                }
              }
              case 'Node.js':
                return undefined
            }
          default:
            return undefined
        }
      }
      if (!this.isMute) {
        switch (this.getEnv()) {
          case 'Surge':
          case 'Loon':
          case 'Stash':
          case 'Shadowrocket':
          default:
            $notification.post(title, subt, desc, toEnvOpts(opts))
            break
          case 'Quantumult X':
            $notify(title, subt, desc, toEnvOpts(opts))
            break
          case 'Node.js':
            break
        }
      }
      if (!this.isMuteLog) {
        let logs = ['', '==============📣系统通知📣==============']
        logs.push(title)
        subt ? logs.push(subt) : ''
        desc ? logs.push(desc) : ''
        console.log(logs.join('\n'))
        this.logs = this.logs.concat(logs)
      }
    }

    log(...logs) {
      if (logs.length > 0) {
        this.logs = [...this.logs, ...logs]
      }
      console.log(logs.join(this.logSeparator))
    }

    logErr(err, msg) {
      switch (this.getEnv()) {
        case 'Surge':
        case 'Loon':
        case 'Stash':
        case 'Shadowrocket':
        case 'Quantumult X':
        default:
          this.log('', `❗️${this.name}, 错误!`, err)
          break
        case 'Node.js':
          this.log('', `❗️${this.name}, 错误!`, err.stack)
          break
      }
    }

    wait(time) {
      return new Promise((resolve) => setTimeout(resolve, time))
    }

    done(val = {}) {
      const endTime = new Date().getTime()
      const costTime = (endTime - this.startTime) / 1000
      this.log('', `🔔${this.name}, 结束! 🕛 ${costTime} 秒`)
      this.log()
      switch (this.getEnv()) {
        case 'Surge':
        case 'Loon':
        case 'Stash':
        case 'Shadowrocket':
        case 'Quantumult X':
        default:
          $done(val)
          break
        case 'Node.js':
          process.exit(1)
      }
    }
  })(name, opts)
}
