param([string]$Original = (Join-Path $PSScriptRoot 'link-map/template.html'))
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $root 'references/rendered/IMP-2026-links-wiki-updated.html'
function Enc([string]$s) { [Net.WebUtility]::HtmlEncode($s) }
# Only project sources may be carried over from the historical HTML.
function IsProjectSource([string]$url) {
    $uri = $null
    if (-not [uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri)) { return $false }
    if ($uri.Scheme -notin @('http','https')) { return $false }
    $domain = $uri.Host.ToLowerInvariant()
    $excluded = '(^|\.)(hh\.ru|jobscan\.co|tealhq\.com|kickresume\.com|indeed\.com|greenhouse\.com|hireseeker\.ru|career\.habr\.com|career\.ozon\.ru|ozon\.tech|education\.tbank\.ru|t\.me|telegram\.me|diplom-it\.ru|itdiplom\.ru|sprinthost\.ru|miro\.com|vk\.ru|console\.yandex\.cloud|scale\.yandex\.cloud|attacker\.com|evil\.example)$'
    if ($domain -match $excluded) { return $false }
    $decoded = [uri]::UnescapeDataString($url)
    if ($decoded -match '(?i)(/workspaces/[^/]+/keys|/vacanc|/resumes?([/?#_-]|$)|/resume-|/job-search|/showcaptcha|[?&](token|access_token|api_key|signature|sig)=|github\.com/NIKITOOOK|резюме|стажиров|написани[ея].*диплом|заказ.*диплом)') { return $false }
    return $true
}
function Key([string]$url) {
    $uri = [uri]$url.Replace('\&','&')
    $query = @($uri.Query.TrimStart('?') -split '&' | Where-Object { $_ -and $_ -notmatch '^(utm_[^=]*|ref)=' })
    return $uri.GetLeftPart([UriPartial]::Path).TrimEnd('/') + $(if ($query.Count) { '?' + ($query -join '&') }) + $uri.Fragment
}
$html = Get-Content -LiteralPath $Original -Raw
$cards = [Collections.Generic.List[string]]::new()
$keys = @{}
$statuses = @{}
$statusText = Get-Content -LiteralPath (Join-Path $root 'wiki/Источники_и_статусы.md') -Raw
foreach ($m in [regex]::Matches($statusText, '\| \[([^\]]+)\]\((https?://[^)]+)\) \| ([^|]+) \|')) {
    $statuses[(Key $m.Groups[2].Value)] = $m.Groups[3].Value.Trim()
}
foreach ($sourceCard in (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'link-map/cards.json') -Raw | ConvertFrom-Json)) {
    $card = [string]$sourceCard
    $href = [regex]::Match($card, '<a class="title" href="([^"]+)"')
    $url = [Net.WebUtility]::HtmlDecode($href.Groups[1].Value)
    if (-not (IsProjectSource $url)) { continue }
    if ($url -match '^https?://') {
        $key = Key $url
        $keys[$key] = $true
        $status = if ($statuses.ContainsKey($key)) { 'По отчёту другого агента: ' + $statuses[$key] + '. Нами при переносе не проверено.' } else { 'Исходная карта: статус чтения не установлен этим обновлением.' }
        $card = $card.Replace('</article>', '<p class="meta verification">' + (Enc $status) + '</p></article>')
    }
    $cards.Add($card)
}
$originalCount = $cards.Count
$extra = 0
foreach ($source in @('wiki/Полезные_ссылки_и_ресурсы.md', 'wiki/Источники_и_статусы.md')) {
    $text = Get-Content -LiteralPath (Join-Path $root $source) -Raw
    foreach ($m in [regex]::Matches($text, '\[([^\]]+)\]\((https?://[^)\s]+)\)')) {
        $url = $m.Groups[2].Value.Replace('\&','&')
        if (-not (IsProjectSource $url)) { continue }
        $key = Key $url
        if ($keys.ContainsKey($key)) { continue }
        $keys[$key] = $true
        $label = $m.Groups[1].Value.Replace('**','')
        $cat = 'Дополнение из Wiki'
        $status = if ($statuses.ContainsKey($key)) { 'По отчёту другого агента: ' + $statuses[$key] + '. Нами при переносе не проверено.' } else { 'Добавлено из подборки пользователя; проверка доступности и содержания не выполнена в этом переносе.' }
        $search = Enc ("$label $url $cat $status".ToLowerInvariant())
        $u = Enc $url
        $cards.Add(@"
<article class="card" data-cat="$cat" data-search="$search">
<div class="topline"><span class="badge">Добавлено 01.10.2026</span></div>
<a class="title" href="$u" target="_blank" rel="noopener noreferrer">$(Enc $label)</a>
<div class="url">$u</div><p class="meta verification">$(Enc $status)</p>
<div class="actions"><a href="$u" target="_blank" rel="noopener noreferrer">Открыть ↗</a></div>
</article>
"@)
        $extra++
    }
}
$html = [regex]::Replace($html, '(?s)(<div id="grid" class="grid">).*?(</div>\s*<div id="empty")', [Text.RegularExpressions.MatchEvaluator]{param($m) $m.Groups[1].Value + ($cards -join [Environment]::NewLine) + $m.Groups[2].Value})
# Rebuild category counts from the retained cards.
$counts = [ordered]@{}
foreach ($card in $cards) {
    $category = [Net.WebUtility]::HtmlDecode([regex]::Match($card, 'data-cat="([^"]+)"').Groups[1].Value)
    if (-not $counts.Contains($category)) { $counts[$category] = 0 }
    $counts[$category]++
}
$filters = '<button class="filter active" data-cat="__all__">Все <span>' + $cards.Count + '</span></button>'
foreach ($category in $counts.Keys) {
    $filters += '<button class="filter" data-cat="' + (Enc $category) + '">' + (Enc $category) + ' <span>' + $counts[$category] + '</span></button>'
}
$html = [regex]::Replace($html, '(?s)(<aside><div class="filters">).*?(</div></aside>)', [Text.RegularExpressions.MatchEvaluator]{param($m) $m.Groups[1].Value + $filters + $m.Groups[2].Value})
$html = [regex]::Replace($html, '(?s)<div class="stats">.*?</div>\s*</div>', '<div class="stats"><div class="stat">Источников проекта: <b>' + $cards.Count + '</b></div><div class="stat">Категорий: <b>' + $counts.Count + '</b></div><div class="stat">Показано: <b id="shown">' + $cards.Count + '</b></div></div>')

$addition = @'
<section class="update-note">
<h2>Дополнение: источники и результаты поиска</h2>
<p>Источники исследования многоуровневой защиты ИИ-агентов. Статусы чтения из внешнего отчёта указаны с атрибуцией; перенос ссылки не подтверждает её проверку.</p>
<p><a href="../../wiki/site/index.html">Открыть Wiki проекта</a> · <a href="#attempts">Что не удалось получить</a> · <a href="#source-list">Источники по теме проекта</a> · <a href="#debug-note">Поиск при отладке</a></p>
<p><a href="../../wiki/методы/README.md">Методы защиты</a> · <a href="../../wiki/Реализованные_политики.md">Реализации, код и тесты</a> · <a href="../../labs/01-agt-budgets/Отчёт_пилота_20260929.md">Результат AGT-пилота</a></p><p>Поиск и категории фильтруют карточки источников. Связи конкретных методов с кодом и тестами приведены в Wiki.</p>
'@
foreach ($item in @(
    @('attempts','Проверки по теме проекта','wiki/Неудавшиеся_проверки.md'),
    @('source-list','Источники и статусы проверки','wiki/Источники_и_статусы.md'),
    @('debug-note','Заметка: поиск при отладке','wiki/Поиск_при_отладке.md')
)) {
    $text = Get-Content -LiteralPath (Join-Path $root $item[2]) -Raw
    $addition += '<details id="' + $item[0] + '"><summary>' + $item[1] + '</summary><pre>' + (Enc $text) + '</pre></details>'
}
$addition += '</section>'
$html = $html.Replace('<div id="grid" class="grid">', $addition + '<div id="grid" class="grid">')
$html = $html.Replace('</style>', '.update-note{margin-bottom:24px}.update-note a{color:var(--accent)}.update-note details{margin:12px 0;border-top:1px solid var(--line);padding-top:10px}.update-note summary{cursor:pointer;font-weight:650}.update-note pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 system-ui;max-height:65vh;overflow:auto;padding:12px}details[id]{scroll-margin-top:150px}a:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}</style>')
$html = $html.Replace('<title>ИМП 2026 — база ссылок</title>', '<title>ИМП 2026 — база ссылок · дополнено 01.10.2026</title>')
New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
[IO.File]::WriteAllText($destination, $html, [Text.UTF8Encoding]::new($false))
[pscustomobject]@{Output=$destination;OriginalCards=$originalCount;AddedCards=$extra;TotalCards=$cards.Count}

