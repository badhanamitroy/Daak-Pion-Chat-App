<?php
// tests/verify_persistent_browser_restart_http.php — Tests real HTTP life-cycle with Apache
declare(strict_types=1);

$baseUrl = 'http://127.0.0.1/Daakpion';

echo "1. Performing initial login with remember_me=1 via HTTP POST...\n";

$ch = curl_init("{$baseUrl}/php/userlogin.php");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'email'       => 'test_direct@example.com',
    'password'    => 'TestPassword123!',
    'remember_me' => '1'
]));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
curl_setopt($ch, CURLOPT_HEADER, true);

$response = curl_exec($ch);
$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$headers = substr($response, 0, $headerSize);
$body = substr($response, $headerSize);
curl_close($ch);

echo " - Login Response Body: {$body}\n";
assert(strpos($body, '"success":true') !== false, "Login must be successful");
assert(strpos($body, '"redirect":"user-profile.php"') !== false, "Redirect must be user-profile.php");

// Extract daakpion_remember cookie
preg_match('/Set-Cookie:\s*daakpion_remember=([^;]+)/i', $headers, $matches);
assert(!empty($matches[1]), "daakpion_remember cookie must be present in Set-Cookie");
$rememberCookie = $matches[1];
echo " - Captured daakpion_remember cookie: " . substr($rememberCookie, 0, 20) . "...\n";

echo "\n2. Simulating browser termination (discarding PHPSESSID)...\n";
echo " - Sending GET to {$baseUrl}/php/user-profile.php with ONLY daakpion_remember cookie...\n";

$ch2 = curl_init("{$baseUrl}/php/user-profile.php");
curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch2, CURLOPT_COOKIE, "daakpion_remember={$rememberCookie}");
curl_setopt($ch2, CURLOPT_HEADER, true);
curl_setopt($ch2, CURLOPT_FOLLOWLOCATION, false); // Do not follow redirects automatically

$response2 = curl_exec($ch2);
$httpCode2 = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
$headerSize2 = curl_getinfo($ch2, CURLINFO_HEADER_SIZE);
$headers2 = substr($response2, 0, $headerSize2);
$body2 = substr($response2, $headerSize2);
curl_close($ch2);

echo " - HTTP Status Code: {$httpCode2}\n";
assert($httpCode2 === 200, "user-profile.php must return HTTP 200 (not redirect to index.html)");
assert(strpos($body2, 'Direct User') !== false, "user-profile.php must render Direct User");
echo " - Successfully accessed profile page without re-authenticating!\n";

// Check if a new PHPSESSID was established and rotated remember cookie was issued
preg_match('/Set-Cookie:\s*PHPSESSID=([^;]+)/i', $headers2, $sessMatches);
assert(!empty($sessMatches[1]), "A new PHP session must be initiated");
echo " - New restored PHPSESSID: " . substr($sessMatches[1], 0, 15) . "...\n";

preg_match('/Set-Cookie:\s*daakpion_remember=([^;]+)/i', $headers2, $rotMatches);
assert(!empty($rotMatches[1]), "daakpion_remember must be rotated upon restoration");
echo " - Rotated daakpion_remember cookie issued: " . substr($rotMatches[1], 0, 20) . "...\n";

echo "\n3. Testing Root Entrypoint (index.php) automatic redirect for returning user...\n";
$ch3 = curl_init("{$baseUrl}/index.php");
curl_setopt($ch3, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch3, CURLOPT_COOKIE, "daakpion_remember={$rotMatches[1]}");
curl_setopt($ch3, CURLOPT_HEADER, true);
curl_setopt($ch3, CURLOPT_FOLLOWLOCATION, false);

$response3 = curl_exec($ch3);
$httpCode3 = curl_getinfo($ch3, CURLINFO_HTTP_CODE);
$headerSize3 = curl_getinfo($ch3, CURLINFO_HEADER_SIZE);
$headers3 = substr($response3, 0, $headerSize3);
curl_close($ch3);

echo " - index.php HTTP Status Code: {$httpCode3}\n";
assert($httpCode3 === 302, "index.php must issue 302 redirect for returning user");
assert(preg_match('/Location:\s*php\/user-profile\.php/i', $headers3) === 1, "Redirect location must be php/user-profile.php");
echo " - index.php automatically redirects returning authenticated user to user-profile.php!\n";

echo "\n=========================================================\n";
echo "  REAL HTTP BROWSER-LIFECYCLE TEST PASSED WITH 100% SUCCESS!\n";
echo "=========================================================\n";
