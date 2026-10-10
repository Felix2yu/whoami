(function () {
  'use strict';

  // 只采集、只回报；判定与文案全部留在服务端，避免两边规则漂移。
  function pick(obj, keys) {
    var out = {};
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (obj && obj[k] !== undefined && obj[k] !== null) out[k] = obj[k];
    }
    return out;
  }

  function readGPU() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { error: '无 WebGL 上下文' };
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      var out = {};
      if (ext) {
        out.vendor = String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '');
        out.renderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '');
      } else {
        out.vendor = String(gl.getParameter(gl.VENDOR) || '');
        out.renderer = String(gl.getParameter(gl.RENDERER) || '');
        out.error = '浏览器未放开 unmasked 参数';
      }
      return out;
    } catch (e) {
      return { error: String((e && e.name) || e) };
    }
  }

  function readHints() {
    var ud = navigator.userAgentData;
    if (!ud || typeof ud.getHighEntropyValues !== 'function') {
      return Promise.resolve({ hintsUnavailable: true, brands: (ud && ud.brands) || [] });
    }
    return ud
      .getHighEntropyValues(['platform', 'platformVersion', 'architecture', 'bitness', 'model', 'fullVersionList'])
      .then(function (v) {
        var list = v.fullVersionList || ud.brands || [];
        var brands = [];
        for (var i = 0; i < list.length && i < 32; i++) {
          if (!list[i] || !list[i].brand) continue;
          brands.push({ brand: String(list[i].brand), version: String(list[i].version || '') });
        }
        return {
          platform: v.platform,
          platformVersion: v.platformVersion,
          architecture: v.architecture,
          bitness: v.bitness,
          model: v.model,
          brands: brands,
          hintsUnavailable: false
        };
      })
      .catch(function () {
        return { hintsUnavailable: true, brands: ud.brands || [] };
      });
  }

  function collect(hints) {
    var langs = navigator.languages || (navigator.language ? [navigator.language] : []);
    var tz = '';
    try {
      tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (e) {
      tz = '';
    }
    var screen = pick(window.screen, ['width', 'height']);
    screen.dpr = Math.round(window.devicePixelRatio || 1);

    var body = pick(hints, ['platform', 'platformVersion', 'architecture', 'bitness', 'model', 'hintsUnavailable']);
    body.brands = hints.brands || [];
    body.gpu = readGPU();
    body.userAgent = navigator.userAgent || '';
    // navigator.platform 不受安全上下文限制，是 http 部署下唯一还能说出系统家族的字段。
    body.navigatorPlatform = navigator.platform || '';
    body.languages = langs.slice(0, 16);
    body.timezone = tz;
    body.screen = screen;
    if (navigator.hardwareConcurrency) body.cores = navigator.hardwareConcurrency;
    if (navigator.deviceMemory) body.memory = navigator.deviceMemory;
    if (navigator.maxTouchPoints) body.touchPoints = navigator.maxTouchPoints;
    return body;
  }

  // note 在 #report 末尾插一行状态文字并返回节点，调用方持有引用以便更新或随替换消失。
  function note(text) {
    var host = document.getElementById('report');
    if (!host) return null;
    var p = document.createElement('p');
    p.className = 'muted';
    p.textContent = text;
    host.appendChild(p);
    return p;
  }

  // reportHeight 把当前内容高度发给宿主页面，宿主据此调整 iframe 高度。
  // 只发 type 与 height 两个字段；targetOrigin 用 '*' 是因为宿主可能是任意跨源页面。
  function reportHeight() {
    if (window.parent === window) return;
    try {
      window.parent.postMessage({ type: 'whoami:height', height: document.documentElement.scrollHeight }, '*');
    } catch (e) { /* 宿主不监听也没有副作用 */ }
  }

  function send(body) {
    var status = note('正在合并浏览器端回报…');
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 3000);
    // 带上 location.search：?hide=/?only=/?embed= 必须传给 /report，
    // 否则回报片段替换 #report 后卡片开关会全部失效。
    fetch('report' + location.search, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'omit',
      signal: ctrl.signal
    })
      .then(function (r) {
        clearTimeout(timer);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.text();
      })
      .then(function (html) {
        // 整块替换会连同加载提示一起清掉，无需手动移除。
        var host = document.getElementById('report');
        if (host) host.innerHTML = html;
        // 替换后内容高度会变，重新通知宿主。
        reportHeight();
      })
      .catch(function (e) {
        clearTimeout(timer);
        if (!status) return;
        var msg = e && e.name === 'AbortError' ? '3 秒超时' : (e && e.message) || e;
        status.textContent = '浏览器端回报失败（' + msg + '），以上仅为服务端信号 ';
        var retry = document.createElement('button');
        retry.type = 'button';
        retry.className = 'linklike';
        retry.textContent = '重试';
        retry.addEventListener('click', function () {
          status.remove();
          send(body);
        });
        status.appendChild(retry);
      });
  }

  // summaryText 从服务端渲染好的 DOM 组装纯文本结论，页面文案仍只有服务端一套。
  function summaryText() {
    var lines = [];
    var rows = document.querySelectorAll('main table.rows > tbody > tr');
    for (var i = 0; i < rows.length; i++) {
      var th = rows[i].children[0];
      var td = rows[i].children[1];
      if (!th || !td) continue;
      var v = td.querySelector('.v');
      var line = th.textContent + '：' + (v ? v.textContent : '');
      var notes = [];
      for (var j = 0; j < td.children.length; j++) {
        var el = td.children[j];
        // 行内说明是 span.muted，接在当前行尾；<p class="muted"> 是独立的一行理由。
        if (el.tagName === 'P') notes.push(el.textContent);
        else if (el.classList.contains('muted')) line += '　' + el.textContent;
      }
      lines.push(line);
      lines = lines.concat(notes);
    }
    var status = document.querySelectorAll('main > p.muted');
    for (var k = 0; k < status.length; k++) {
      lines.push(status[k].textContent);
    }
    var foot = document.querySelector('footer .muted');
    if (foot) lines.push(foot.textContent);
    return lines.join('\n');
  }

  // legacyCopy 用隐藏 textarea + execCommand 复制，返回是否成功。
  function legacyCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  // copyText 返回 Promise<boolean>。Clipboard API 会因文档未聚焦等原因拒绝，
  // 必须接住并降级到 execCommand，否则失败会变成未捕获异常且按钮毫无反馈。
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(
        function () { return true; },
        function () { return legacyCopy(text); }
      );
    }
    return Promise.resolve(legacyCopy(text));
  }

  // 委托监听：#report 会被回报片段整块替换，按钮节点必须走事件委托。
  function bindCopy() {
    document.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.classList || !t.classList.contains('copybtn')) return;
      copyText(summaryText()).then(function (ok) {
        var old = t.textContent;
        t.textContent = ok ? '已复制' : '复制失败';
        setTimeout(function () { t.textContent = old; }, 2000);
      });
    });
  }

  function run() {
    bindCopy();
    // 自适应高度：初始渲染、窗口变化、资源加载完毕都重新上报一次。
    reportHeight();
    window.addEventListener('resize', reportHeight);
    window.addEventListener('load', reportHeight);
    // 页面已经在跑，说明 JavaScript 可用；这一条本身就是「未回报」提示的修正。
    readHints().then(function (hints) {
      send(collect(hints));
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
