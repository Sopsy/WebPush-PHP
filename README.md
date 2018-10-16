# WebPush-PHP
PHP Web Push library

Supports only ES256 and aes128gcm.

## Usage
```
$endpoint = 'https://updates.push.services.mozilla.com/wpush/v2/xxxxxxx';
$auth = Base64Url::decode('AuthKeyFromBrowser');
$receiverPublicKey = Base64Url::decode('PublicKeyFromBrowser');

$serverKey = file_get_contents('ec-privatekey.pem');
$receiverPublicPem = KeyConverter::p256PublicKeyToPem($receiverPublicKey);

$signer = new ES256($serverKey);

$endpointParts = parse_url($endpoint);
$jwt = new JwtGenerator($signer);
$jwt->setPayload([
    'aud' => $endpointParts['scheme'] . '://' . $endpointParts['host'],
    'exp' => time() + (3600 * 12), // Should be less than 24 hours, see JWT TTL
    'sub' => 'https://myurl.com/',
    //or: 'sub' => 'mailto:email@example.com',
]);

$notification = new Notification($jwt, $endpoint, $serverKey);

$payload = new Aes128Gcm(new OpenSSL(), $auth, $receiverPublicPem);
$payload->set('Hello world!');
$notification->setPayload($payload);

$notification->send();
```