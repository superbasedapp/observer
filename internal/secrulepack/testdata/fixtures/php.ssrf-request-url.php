<?php

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Http;

function preview($request)
{
    $url = $_GET['url'];
    // ruleid: php.ssrf-request-url
    $ch = curl_init($url);
    $ch2 = curl_init();
    // ruleid: php.ssrf-request-url
    curl_setopt($ch2, CURLOPT_URL, $_POST['feed']);
    // ruleid: php.ssrf-request-url
    $resp = Http::get($request->input('callback'));
    $client = new Client();
    // ruleid: php.ssrf-request-url
    $page = $client->request('GET', $request->query('target'));
    // ruleid: php.ssrf-request-url
    $hook = $client->post($_POST['hook'] . '/notify');
    // ruleid: php.ssrf-request-url
    $api = new Client(['base_uri' => $_GET['api']]);
    return [$ch, $resp, $page, $hook, $api];
}

function safe($request)
{
    $client = new Client();
    // ok: php.ssrf-request-url
    $user = $client->get('https://api.example.com/users/' . $request->input('id'));
    // ok: php.ssrf-request-url
    $ch = curl_init("https://api.example.com/search?q=" . urlencode($_GET['q']));
    // ok: php.ssrf-request-url
    $resp = Http::get("https://status.example.com/v1/{$_GET['component']}");
    // ok: php.ssrf-request-url
    $health = Http::get('https://status.example.com/health', ['id' => $_GET['id']]);
    return [$user, $ch, $resp, $health];
}

// The program's own values, not request input.
function poll(string $endpoint)
{
    // ok: php.ssrf-request-url
    return curl_init($endpoint);
}
