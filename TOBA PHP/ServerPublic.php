<?php
header('Content-type: text/plain');

if(strpos($_SERVER['REQUEST_URI'],"ServerPublic.php")){
    require_once 'Utils.php';
    PlainDie("No API Calls!");
}

include "init.php";

$filename = "ServerKeys/PublicKey.puk";
$handle = fopen($filename, "r");
$puk = fread($handle, filesize($filename));
fclose($handle);

echo toBase64(PublicKeyToBinary($puk));