# WebPush-PHP
PHP Web Push library

Supports only ES256 and aes128gcm.

## Usage
```PHP
$endpoint = 'https://updates.push.services.mozilla.com/wpush/v2/xxxxxxx';
$auth = Base64Url::decode('AuthKeyFromBrowser');
$receiverPublicKey = Base64Url::decode('PublicKeyFromBrowser');

$serverKey = file_get_contents('ec-privatekey.pem');
$receiverPublicPem = KeyConverter::p256PublicKeyToPem($receiverPublicKey);

$endpointParts = parse_url($endpoint);

$jwt = new WebPushJwt(
    new ES256($serverKey), // Signer
    $endpointParts['scheme'] . '://' . $endpointParts['host'], // Audience
    3600 * 12, // TTL in seconds, should be less than 24 hours
    'https://myurl.com/', // Subject (or: 'mailto:email@example.com')
);

$message = new PushMessage($jwt, $endpoint, $serverKey);

$payload = new Aes128Gcm(
    new OpenSSL(OpenSSL::KEYTYPE_EC, OpenSSL::CURVE_P256), // Key Factory
    $auth, // User auth key
    $receiverPublicPem, // User public key
    'Hello world!' // Data
  );

$response = $message->send($payload);

if ($response->success()) {
    echo 'Push sent!';
} else {
    echo 'Sending a push failed: (' . $response->code . ') ' . $response->message;
}
```
