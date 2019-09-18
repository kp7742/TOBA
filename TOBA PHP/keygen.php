<?php
header('Content-type: text/plain');

//api url filter
if(strpos($_SERVER['REQUEST_URI'],"keygen.php") || !isset($_GET['uname'])){
    require_once 'Utils.php';
    PlainDie("UserName Not Provided!");
}

$uname = $_GET['uname'];
$folderpath = 'Keys/'.$uname.'/';

include "init.php";

$crypter = Crypter::init();

echo "PrivateKey: " . $crypter->getPrivateKey();
echo "<br><br><br>";
echo "PublicKey: " . $crypter->getPublicKey();

if (!file_exists($folderpath)) {
    mkdir($folderpath, 0777, true);
}

$prk = fopen($folderpath."PrivateKey.prk", "w");
$puk = fopen($folderpath."PublicKey.puk", "w");
$prkbin = fopen($folderpath."PrivateKey.prk.bin", "w");
$pukbin = fopen($folderpath."PublicKey.puk.bin", "w");

fwrite($prk,$crypter->getPrivateKey());
fwrite($puk,$crypter->getPublicKey());
fwrite($prkbin,$crypter->getPrivateKeyBinary());
fwrite($pukbin,$crypter->getPublicKeyBinary());

fclose($prk);
fclose($puk);
fclose($prkbin);
fclose($pukbin);