<?php

namespace  Backend;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Avelibrary
{
    private $secret_key;

    private $encrypt;

    private $encryptSSL;

    private $passphrase;

    public function __construct($secret_key, $encrypt, $encryptSSL, $passphrase)
    {
        $this->secret_key = $secret_key;
        $this->encrypt = $encrypt;
        $this->encryptSSL = $encryptSSL;
        $this->passphrase = $passphrase;
    }

    public function getdata($token, $contentKey)
    {
        $keyPublic = openssl_get_publickey($contentKey);

        $dataToken = JWT::decode($token, new Key($keyPublic, self::$encryptSSL));

        $data = $this->secured_decrypt($dataToken->data);

        return $data;
    }

    private function secured_decrypt($inputData)
    {
        $first_key = base64_decode(self::$secret_key);
        $second_key = base64_decode(self::$passphrase);
        $cypherMethod = 'AES-256-CBC';

        $mix = base64_decode($inputData);
        $iv_length = openssl_cipher_iv_length($cypherMethod);
        $ivX = substr($mix, 0, $iv_length);
        $second_encryptedX = substr($mix, $iv_length, 32);
        $first_encryptedX = substr($mix, $iv_length + 32);

        $data = openssl_decrypt($first_encryptedX, $cypherMethod, $first_key, OPENSSL_RAW_DATA, $ivX);
        $second_encrypted_new = hash_hmac('sha256', utf8_encode($first_encryptedX), $second_key, true);

        if ($second_encryptedX == $second_encrypted_new) {
            return unserialize($data);
        }

        return false;
    }
}
