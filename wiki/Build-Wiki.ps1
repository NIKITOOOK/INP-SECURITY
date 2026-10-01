# Requires PowerShell 7 with ConvertFrom-Markdown. Documentation only.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$outputRoot = Join-Path $PSScriptRoot 'site'
if (-not (Get-Command ConvertFrom-Markdown -ErrorAction SilentlyContinue)) {
    throw 'PowerShell 7 with ConvertFrom-Markdown is required.'
}
function Encode([string]$value) { [System.Net.WebUtility]::HtmlEncode($value) }
Push-Location $projectRoot
try {
    # Explicit public manifest also works in a downloaded ZIP without .git.
    $tracked = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'public-files.json') -Raw | ConvertFrom-Json)
    $newWiki = @()
    $allowed = @{}
    foreach ($path in ($tracked + $newWiki)) {
        if ($path -match '(^/|^[A-Za-z]:|(^|/)\.\.(/|$))') { throw "Invalid manifest path: $path" }
        if ($path -notlike 'wiki/site/*') { $allowed[$path] = $true }
    }
    $documents = @($allowed.Keys | Where-Object { $_ -like '*.md' } | Sort-Object)
    $pages = @{}
    $titles = @{}
    $pageIndex = 0
    foreach ($path in $documents) {
        $pageIndex++
        $pages[$path] = if ($path -eq 'wiki/README.md') { 'index.html' } else { 'p{0:D3}.html' -f $pageIndex }
        $heading = Get-Content -LiteralPath (Join-Path $projectRoot $path) | Where-Object { $_ -match '^# ' } | Select-Object -First 1
        $titles[$path] = if ($heading) { $heading.Substring(2) } else { $path }
    }
    if (-not $pages.ContainsKey('wiki/README.md')) { throw 'Wiki home not found.' }
    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    $groups = [ordered]@{
        'Обзор' = @('wiki/README.md','ПЕРЕД_ОТПРАВКОЙ.md','wiki/методы/README.md','wiki/Реализованные_политики.md','Карта_реализации_многоуровневой_защиты.md')
        'L1 · Вход и результаты' = @($documents | Where-Object { $_ -like 'wiki/методы/L1_*' })
        'L3 · Ограничения' = @($documents | Where-Object { $_ -like 'wiki/методы/L3_*' -or $_ -like 'wiki/методы/AGT_*' })
        'Источники' = @('wiki/Полезные_ссылки_и_ресурсы.md','wiki/Источники_и_статусы.md','wiki/Неудавшиеся_проверки.md','wiki/Поиск_при_отладке.md','wiki/аудит/Индекс_архивов_A1.3.md')
        'Аудит и покрытие L2' = @($documents | Where-Object { $_ -like 'wiki/аудит/*' -and $_ -ne 'wiki/аудит/Индекс_архивов_A1.3.md' })
        'Лабораторные' = @($documents | Where-Object { $_ -like 'labs/*' })
        'Проект и код' = @($documents | Where-Object { $_ -notlike 'wiki/*' -and $_ -notlike 'labs/*' -and $_ -ne 'Карта_реализации_многоуровневой_защиты.md' })
    }
    $css = @'
:root{color-scheme:light;--ink:#233247;--muted:#5d6a7c;--line:#dce3eb;--accent:#175d9c}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:16px/1.65 system-ui,sans-serif}
a{color:var(--accent);text-underline-offset:3px}a:focus-visible{outline:3px solid #ecae44;outline-offset:3px}
.skip{position:absolute;left:-9999px}.skip:focus{left:320px;top:8px;background:white;z-index:9}
aside{position:fixed;inset:0 auto 0 0;width:290px;overflow-y:auto;background:#f5f7fa;border-right:1px solid var(--line);padding:25px 18px}
.brand{font-size:19px;font-weight:750;display:block;text-decoration:none}.caption{color:var(--muted);font-size:12px;margin:6px 0 22px}
details{margin:12px 0}summary{font-size:13px;font-weight:750;cursor:pointer;padding:5px}
nav a{display:block;padding:7px 10px;font-size:13px;line-height:1.45;text-decoration:none;border-radius:5px;margin:2px 0}
nav a:hover{background:#e5edf6}nav a[aria-current=page]{background:#dceafa;color:#124d81;font-weight:650}
main{margin-left:290px;padding:38px clamp(22px,5vw,85px);max-width:1350px}
.meta{font-size:12px;color:var(--muted);border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px;overflow-wrap:anywhere}
h1{font-size:30px;line-height:1.25;margin-top:0}h2{font-size:22px;margin-top:32px}h3{font-size:18px}
pre{background:#f3f6fa;border:1px solid var(--line);padding:16px;overflow:auto;border-radius:7px}
code{font-size:.87em;background:#f3f6fa;overflow-wrap:anywhere}pre code{background:none}
table{border-collapse:collapse;display:block;overflow-x:auto;font-size:14px;margin:20px 0;max-width:100%}
th,td{border:1px solid var(--line);padding:10px 12px;min-width:130px;vertical-align:top}th{background:#edf2f8;text-align:left}
blockquote{border-left:3px solid #aac5df;margin-left:0;padding-left:18px;color:var(--muted)}
.unavailable{color:#7c5261;text-decoration:underline dotted;cursor:help}
footer{border-top:1px solid var(--line);margin-top:40px;padding-top:15px;font-size:12px;color:var(--muted)}
@media(max-width:780px){aside{position:static;width:auto;max-height:42vh;border-bottom:1px solid var(--line)}main{margin:0;padding:24px 18px}h1{font-size:25px}.skip:focus{left:10px}}
@media print{aside,.skip,.meta{display:none}main{margin:0;padding:0}table{display:table}pre{white-space:pre-wrap}}
'@
    foreach ($path in $documents) {
        $markdown = Get-Content -LiteralPath (Join-Path $projectRoot $path) -Raw
        $html = (ConvertFrom-Markdown -InputObject $markdown).Html
        # Keep renderer IDs and add Unicode heading aliases used by Markdown links.
        $headingIds = @{}
        $html = [regex]::Replace($html, '(?is)<h([1-6])\b[^>]*>(.*?)</h\1>', {
            param($heading)
            $text = [Net.WebUtility]::HtmlDecode([regex]::Replace($heading.Groups[2].Value, '<[^>]+>', ''))
            $slug = [regex]::Replace($text.ToLowerInvariant(), '[^\p{L}\p{N}\p{M}_\s-]', '')
            $slug = [regex]::Replace($slug, '\s', '-')
            $baseSlug = $slug
            if ($headingIds.ContainsKey($baseSlug)) {
                $headingIds[$baseSlug]++
                $slug += '-' + $headingIds[$baseSlug]
            } else { $headingIds[$baseSlug] = 0 }
            if ($slug -and $heading.Value -notmatch ('id="' + [regex]::Escape($slug) + '"')) {
                return '<span id="' + (Encode $slug) + '"></span>' + $heading.Value
            }
            return $heading.Value
        })
        # Never execute embedded scripts or load remote assets from documents.
        $html = [regex]::Replace($html, '(?is)<script\b[^>]*>.*?</script>', '')
        $html = [regex]::Replace($html, '(?is)<a\b[^>]*href="([^"]*)"[^>]*>(.*?)</a>', {
            param($match)
            $href = [System.Net.WebUtility]::HtmlDecode($match.Groups[1].Value)
            $label = $match.Groups[2].Value
            if ($href -match '^https?://') { return '<a href="' + (Encode $href) + '" rel="noreferrer">' + $label + '</a>' }
            if ($href.StartsWith('#')) { return $match.Value }
            if ($href -match '^[a-zA-Z][a-zA-Z0-9+.-]*:' -or $href.StartsWith('//')) {
                return '<span class="unavailable" title="Внешний или локальный путь не включён в сборку">' + $label + '</span>'
            }
            $parts = $href -split '#',2
            $fragment = if ($parts.Count -gt 1) { '#' + $parts[1] } else { '' }
            $parent = Split-Path (Join-Path $projectRoot $path) -Parent
            $resolved = [IO.Path]::GetFullPath((Join-Path $parent ([uri]::UnescapeDataString($parts[0]))))
            $relative = [IO.Path]::GetRelativePath($projectRoot, $resolved).Replace('\','/')
            if ($relative -eq 'wiki/site/index.html') { return '<a href="index.html">' + $label + '</a>' }
            if ($pages.ContainsKey($relative) -and $fragment -notmatch '^#L\d+') {
                return '<a href="' + (Encode ($pages[$relative] + $fragment)) + '">' + $label + '</a>'
            }
            if ($allowed.ContainsKey($relative) -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                $url = '../../' + (($relative -split '/' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/')
                return '<a href="' + (Encode ($url + $fragment)) + '" title="Исходный файл; переход к строке зависит от просмотрщика">' + $label + '</a>'
            }
            return '<span class="unavailable" title="Файл не включён в Git-комплект; см. Markdown-исходник">' + $label + '</span>'
        })
        $nav = ''
        foreach ($group in $groups.GetEnumerator()) {
            $links = ''
            foreach ($target in $group.Value) {
                if (-not $pages.ContainsKey($target)) { continue }
                $current = if ($target -eq $path) { ' aria-current="page"' } else { '' }
                $links += '<a href="' + $pages[$target] + '"' + $current + '>' + (Encode $titles[$target]) + '</a>'
            }
            $expanded = if ($group.Name -in @('Обзор','L1 · Вход и результаты','L3 · Ограничения','Источники') -or $group.Value -contains $path) { ' open' } else { '' }
            $nav += '<details' + $expanded + '><summary>' + (Encode $group.Name) + '</summary>' + $links + '</details>'
        }
        $source = '../../' + (($path -split '/' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/')
        $page = @"
<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>$(Encode $titles[$path]) — Security Lab Wiki</title><style>$css</style></head>
<body><a class="skip" href="#content">К содержимому</a><aside><a class="brand" href="index.html">Security Lab · Wiki</a>
<p class="caption">Многоуровневая защита агента<br>Документация ≠ доказательство испытания</p><nav aria-label="Разделы Wiki">$nav</nav></aside>
<main id="content"><div class="meta">$(Encode $path) · <a href="$source">Markdown-исходник</a></div>
$html
<footer>Локальная HTML-сборка из Markdown. Правки вносить в исходные .md, затем повторить сборку. Без сервера и внешних зависимостей.</footer></main></body></html>
"@
        [IO.File]::WriteAllText((Join-Path $outputRoot $pages[$path]), $page, [Text.UTF8Encoding]::new($false))
    }
    Write-Output "Built $($documents.Count) pages: $outputRoot/index.html"
} finally { Pop-Location }

