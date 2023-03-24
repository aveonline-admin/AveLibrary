<?php

namespace  backendAve\avelibrary;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Avelibrary
{

    private static $secret_key;
    private static $encrypt;
    private static $encryptSSL;
    private static $passphrase;

    public function __construct($secret_key, $encrypt, $encryptSSL, $passphrase)
    {
        $this->secret_key =  $secret_key;
        $this->encrypt    =  $encrypt;
        $this->encryptSSL =  $encryptSSL;
        $this->passphrase =  $passphrase;
    }

    public function GetData($token, $keyPath)
    {
        $keyPublic = openssl_get_publickey(file_get_contents($keyPath));

        $dataToken = JWT::decode($token, new Key($keyPublic, self::$encryptSSL));

        $data = self::secured_decrypt($dataToken->data);

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
        $second_encrypted_new = hash_hmac('sha256', utf8_encode($first_encryptedX), $second_key, TRUE);

        if ($second_encryptedX == $second_encrypted_new) {
            return unserialize($data);
        }
        return false;
    }
}
