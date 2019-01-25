<?php

// Polyfill for PHP7.2 (this new function in PHP7.3 is exactly what we need)
if (!function_exists('openssl_pkey_derive')) {
    function openssl_pkey_derive($peer_pub_key, $priv_key, $keylen = null) {

        if ($keylen !== null) {
            throw new RuntimeException('Key length attribute is not supported');
        }

        $result = shell_exec('/bin/bash -c "/usr/bin/openssl pkeyutl -derive -inkey <(echo -n ' . escapeshellarg($priv_key) . ') '
            . '-peerkey <(echo -n ' . escapeshellarg($peer_pub_key) . ')"');

        if ($result === null) {
            return false;
        }

        return $result;
    }
}