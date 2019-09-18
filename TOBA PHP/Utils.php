<?php

function getMicro(){
    return explode(' ', microtime())[1];
}

function readFileData($path){
    $file = fopen($path,"r") or die();
    $data = fread($file,filesize($path));
    fclose($file);
    return $data;
}

function isFileExist($path){
    if (file_exists($path)) {
        return 1;
    }
    return 0;
}

function toBase64($data){
    return base64_encode($data);
}

function fromBase64($data){
    return base64_decode($data);
}

function urlsafe_b64encode($string) {
    $data = base64_encode($string);
    $data = str_replace(array('+','/','='),array('-','_',''),$data);
    return $data;
}

function urlsafe_b64decode($string) {
    $data = str_replace(array('-','_'),array('+','/'),$string);
    $mod4 = strlen($data) % 4;
    if ($mod4) {
        $data .= substr('====', $mod4);
    }
    return base64_decode($data);
}

function toJson($data){
    return json_encode($data);
}

function fromJson($data){
    return json_decode($data, true);
}

function PlainDie($status = ""){
    header('Content-type: text/plain');
    die($status);
}

function sha256($data){
    return hash('sha256', $data);
}

function PublicKeyToBinary($publickey){
    $publickey = str_replace("-----BEGIN PUBLIC KEY-----","", $publickey);
    $publickey = str_replace("-----END PUBLIC KEY-----","", $publickey);
    $publickey = trim($publickey);
    return fromBase64($publickey);
}

function PrivateKeyToBinary($privatekey){
    $privatekey = str_replace("-----BEGIN RSA PRIVATE KEY-----","", $privatekey);
    $privatekey = str_replace("-----END RSA PRIVATE KEY-----","", $privatekey);
    $privatekey = trim($privatekey);
    return fromBase64($privatekey);
}