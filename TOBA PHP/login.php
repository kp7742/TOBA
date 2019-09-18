<?php
//api url filter
if(strpos($_SERVER['REQUEST_URI'],"login.php") || !isset($_POST['token'])){
    require_once 'Utils.php';
    PlainDie("Login Wrong!");
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

/*
 * Sample Token Array:
 * array(4) {
 * ["Data"]=> array(2) { ["UID"]=> string(36) "KP7742,F7f059d4e72f7ac6f,CriticalOps" ["userid"]=> string(6) "KP7742" }
 * ["id"]=> int(1)
 * ["validity"]=> int(12000)
 * ["Hash"]=> array(2) { ["algo"]=> string(7) "SHA-256" ["hash"]=> string(44) "6ml/QmCh0vu3j7N6Yk78rFoYFtGuS4UUis7QQ/6snPk=" }
 * }
*/

//Id Validator
$id = $tokarr['id'];
if($id != 1) {
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

//Folder Handler
$folderpath = 'Keys/'.$uname.'/';
if (!isFileExist($folderpath)) {
    mkdir($folderpath, 0777, true);
}

//KeyPair Handler
if(!isFileExist($folderpath."PrivateKey.prk")){
    $keygen = Crypter::init();
    $prk = fopen($folderpath."PrivateKey.prk", "w");
    $puk = fopen($folderpath."PublicKey.puk", "w");
    $prkbin = fopen($folderpath."PrivateKey.prk.bin", "w");
    $pukbin = fopen($folderpath."PublicKey.puk.bin", "w");

    fwrite($prk,$keygen->getPrivateKey());
    fwrite($puk,$keygen->getPublicKey());
    fwrite($prkbin,$keygen->getPrivateKeyBinary());
    fwrite($pukbin,$keygen->getPublicKeyBinary());

    fclose($prk);
    fclose($puk);
    fclose($prkbin);
    fclose($pukbin);
}

$sign = toBase64($crypter->signByPrivate($privatekey, $encdata));
//echo $crypter->verifyByPublic($publickey, $encdata, fromBase64($sign));

$userprivatekey = readFileData($folderpath."PrivateKey.prk");
$data = toBase64(
    toJson(
        array(
            "private" => toBase64(PrivateKeyToBinary($userprivatekey)),
            "authdata" => $encdata,
            "serversignature" => $sign
        )
    )
);

//Acknowledgment Token
$acktoken = array(
    "id" => 2,
    "validity" => 12000,
    "Data" => $data,
    "Hash" => array("algo" => "SHA-256", "hash" => sha256($data))
);

echo toBase64(toJson($acktoken));