const fs = require('fs/promises');

const sourceUrls = [
  "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/subscriptions/mix-normal.txt",
  "https://github.com/barry-far/V2ray-Config/raw/refs/heads/main/All_Configs_Sub.txt",
  "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
  "https://raw.githubusercontent.com/0xAbolfazl/PyroConfig/main/Configs/vless.txt",
  "https://raw.githubusercontent.com/1man01/sub-aggregator/main/merged_subscription_germany.txt",
  "https://raw.githubusercontent.com/Argh73/V2Ray-Vault/main/data/sub/protocols/trojan.txt",
  "https://raw.githubusercontent.com/azatabd/v2ray_fetch/main/trojan.txt",
  "https://raw.githubusercontent.com/ctsfork/web/main/vpn/v2/youneed.win_trojan.txt",
  "https://raw.githubusercontent.com/mrvcoder/V2rayCollector/refs/heads/main/trojan_iran.txt",
  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/trojan.txt",
  "https://raw.githubusercontent.com/hamedp-71/Trojan/main/hp.txt",
  "https://gitlab.com/avencores/goida-vpn-configs/-/raw/main/githubmirror/1.txt",
  "https://raw.githubusercontent.com/mohammadaz2/v2rayConfigsForYou/main/sub/trojan.txt",
  "https://gitlab.com/avencores/goida-vpn-configs/-/raw/main/githubmirror/1.txt",
  "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
  "https://raw.githubusercontent.com/ezgy1984/Aggregated-Split-ProxyList/refs/heads/main/trojan.txt",
  "https://raw.githubusercontent.com/pyptom76/pyptom76/main/trojan.txt",
  "https://github.com/Firmfox/Proxify/raw/refs/heads/main/v2ray_configs/separated_by_protocol/trojan.txt",
  "https://github.com/Firmfox/Proxify/raw/refs/heads/main/v2ray_configs/separated_by_protocol/vless.txt",
  "https://raw.githubusercontent.com/flaafix/AetrisVPN-white-list-lite/refs/heads/main/AetrisVPN.txt",
  "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/all/configs.txt",
  "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/trojan",
  "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/trojan_configs.txt",
  "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt"
];

const FREE_IP = "104.18.37.127";

function decodeIfBase64(text) {
  try {
    const cleaned = text.trim().replace(/\s+/g, '');
    const normalized = cleaned.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const decoded = Buffer.from(padded, 'base64').toString('utf8');

    if (decoded.includes('vless://') || decoded.includes('trojan://') || decoded.includes('vmess://')) {
      return decoded;
    }
  } catch (_) {}

  return text;
}

function b64DecodeUtf8(b64) {
  try {
    b64 = b64.trim().replace(/\s/g, '');
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    return Buffer.from(b64, 'base64').toString('utf8');
  } catch { return null; }
}

function b64EncodeUtf8(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

async function main() {
  const results = await Promise.allSettled(
    sourceUrls.map(url =>
      fetch(url, { headers: { 'user-agent': 'Mozilla/5.0' } })
        .then(res => (res.ok ? res.text() : ''))
    )
  );

  const texts = results
    .filter(r => r.status === 'fulfilled' && r.value)
    .map(r => r.value);

  const filteredConfigs = [];
  const seenConfigs = new Set();

  for (let text of texts) {
    let decodedText = text;

    if (!text.includes('vless://') && !text.includes('trojan://') && !text.includes('vmess://')) {
      decodedText = decodeIfBase64(text);
    }

    const lines = decodedText.split(/\r?\n/);

    for (let line of lines) {
      line = line.trim();
      if (!line) continue;

      // ==========================================
      // 1. إضافة VMess
      // ==========================================
      if (line.startsWith('vmess://')) {
        try {
          const cleanLine = line.split('#')[0];
          const b64 = cleanLine.slice(8).trim();
          const jsonStr = b64DecodeUtf8(b64);
          if (!jsonStr) continue;
          
          const config = JSON.parse(jsonStr);

          // شروط: WS + TLS + Port 443
          if (
            String(config.net).toLowerCase() !== 'ws' || 
            String(config.tls).toLowerCase() !== 'tls' || 
            String(config.port) !== '443'
          ) continue;

          const host = String(config.host || config.sni || '').toLowerCase().trim();
          const sni = String(config.sni || config.host || '').toLowerCase().trim();
          if (!host || !sni) continue;

          // منع التكرار
          const signature = `vmess|${config.id}|${host}|${sni}`;
          if (seenConfigs.has(signature)) continue;
          seenConfigs.add(signature);

          // تعديل الـ IP
          config.add = FREE_IP;
          config.host = host;
          config.sni = sni;

          const newB64 = b64EncodeUtf8(JSON.stringify(config));
          filteredConfigs.push("vmess://" + newB64);
        } catch (_) {}
        continue;
      }

      // ==========================================
      // 2. معالجة VLESS و Trojan
      // ==========================================
      const cleanLine = line.split('#')[0].trim();
      if (!cleanLine.startsWith('vless://') && !cleanLine.startsWith('trojan://')) {
        continue;
      }

      try {
        const url = new URL(cleanLine);
        const protocol = url.protocol.replace(':', '').toLowerCase();

        if (
          (protocol !== 'vless' && protocol !== 'trojan') ||
          url.searchParams.get('type') !== 'ws' ||
          url.searchParams.get('security') !== 'tls' ||
          url.port !== '443'
        ) {
          continue;
        }

        const username = url.username.toLowerCase();
        const host = (url.searchParams.get('host') || '').toLowerCase();
        const sni = (url.searchParams.get('sni') || '').toLowerCase();

        const signature = `${protocol}|${username}|${host}|${sni}`;

        if (seenConfigs.has(signature)) continue;
        seenConfigs.add(signature);

        url.hostname = FREE_IP;

        let finalConfig = url.toString();

        const originalRemark = line.split('#')[1];
        if (originalRemark) {
          finalConfig += `#${originalRemark}`;
        }

        filteredConfigs.push(finalConfig);
      } catch (_) {}
    }
  }

  // حفظ الملف كنص عادي (بلا تشفير باش Cloudflare يقدر يقراه)
  await fs.writeFile('sub.txt', filteredConfigs.join('\n'), 'utf8');
  console.log(`✅ Saved ${filteredConfigs.length} configs to sub.txt`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
