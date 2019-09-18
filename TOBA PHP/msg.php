<?php
//api url filter
if(strpos($_SERVER['REQUEST_URI'],"msg.php") || !isset($_POST['token'])){
    require_once 'Utils.php';
    PlainDie("Msg Error!");
}

include 'DB.php';
include 'init.php';

//initialization
$crypter = Crypter::init();
$publickey = readFileData("ServerKeys/PublicKey.puk.bin");
$privatekey = readFileData("ServerKeys/PrivateKey.prk");

//token data
$token = fromBase64($_POST['token']);
$tokarr = json_decode($token, true);

//Id Validator
$id = $tokarr['id'];
if($id != 3) {
    PlainDie("Token ID Wrong!");
}

//Data section decrypter
$encdata = $tokarr['Data'];
$decdata = $crypter->decryptByPrivate($privatekey, fromBase64($encdata));
$data = fromJson($decdata);

//Algorithm Validator
$tokhash = $tokarr['Hash']["hash"];
$newhash = null;

$algo = $tokarr['Hash']["algo"];
switch ($algo) {
    case 'SHA-1':
        $newhash = sha1(toJson($data));
        break;
    case 'SHA-256':
        $newhash = sha256(toJson($data));
        break;
    default:
        PlainDie("Hash Algo Wrong!");
}

//Hash Validator
if ($newhash != $tokhash) {
    PlainDie("Hash Match Failed!");
}

//Signature Validator
$sign = $data["clientsignature"];
if($sign == null || $sign != "F7f059d4e72f7ac6f"){
    PlainDie("Client Signature Wrong!");
}

//Message
$msg = $data["message"];
if($msg == null){
    PlainDie("Message is Null");
}

//Authdata
$authdata = $tokarr["authdata"];
if($authdata == null){
    PlainDie("No Authdata Provided!");
}

//Data section decrypter
$encdata = $authdata;
$decdata = $crypter->decryptByPrivate($privatekey, fromBase64($encdata));
$data = fromJson($decdata);

//Username Validator
$uname = $data["userid"];
if($uname == null){
    PlainDie("Username Null!");
}

$query = $conn->query("SELECT * FROM users WHERE UName = '". $uname. "'");
if($query->num_rows < 1){
    PlainDie("Username Wrong!");
}

//Password Validator
$pass = $data["password"];
if($pass == null){
    PlainDie("Password Null!");
}

$res = $query->fetch_assoc();
if($res['Password'] != $pass){
    PlainDie("Password Wrong!");
}

//KeyPair Handler
$folderpath = 'Keys/'.$uname.'/';
if(!isFileExist($folderpath."PublicKey.puk")) {
    PlainDie("Key Match Not Found!");
}

/*
$keygen = Crypter::init();
$publickey = readFileData($folderpath."PublicKey.puk.bin");
$encdata = toBase64($crypter->encryptByPublic($publickey, $decdata));*/
$encdata = $msg." Ack!";

//Acknowledgment Token
$acktoken = array(
    "id" => 2,
    "validity" => 12000,
    "Data" => $encdata,
    "Hash" => array("algo" => "SHA-256", "hash" => sha256($encdata))
);

echo toBase64(toJson($acktoken));