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
    body.languages = langs.slice(0, 16);
    body.timezone = tz;
    body.screen = screen;
    if (navigator.hardwareConcurrency) body.cores = navigator.hardwareConcurrency;
    if (navigator.deviceMemory) body.memory = navigator.deviceMemory;
    if (navigator.maxTouchPoints) body.touchPoints = navigator.maxTouchPoints;
    return body;
  }

  function note(text) {
    var host = document.getElementById('report');
    if (!host) return;
    var p = document.createElement('p');
    p.className = 'muted';
    p.textContent = text;
    host.appendChild(p);
  }

  function send(body) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 3000);
    fetch('report', {
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
        var host = document.getElementById('report');
        if (host) host.innerHTML = html;
      })
      .catch(function (e) {
        clearTimeout(timer);
        note('浏览器端回报失败（' + e.message + '），以上仅为服务端信号');
      });
  }

  function run() {
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
