<?php
include 'init.php';

$crypter = Crypter::init();
$plaintext = "adcdefghijklmnopqrstuvwxyz";

$publickey = readFileData("Keys/PublicKey.puk.bin");
$privatekey = readFileData("Keys/PrivateKey.prk");

$crypter->loadKey($privatekey,CRYPT_RSA_PRIVATE_FORMAT_PKCS8);
echo "PrivateKey: " . $crypter->getPrivateKey();
echo "<br><br><br>";
echo "PublicKey: " . $crypter->getPublicKey();
echo "<br><br><br>";
$ciphertext = toBase64($crypter->encryptByPublic($publickey, $plaintext));
echo "CipherText: " . $ciphertext;
echo "<br><br><br>";
$signed = $crypter->signByPrivate($privatekey, $plaintext);
echo "Signed Text: " . toBase64($signed);
echo "<br><br><br>";
echo "PlainText: " . $crypter->decryptByPrivate($privatekey, fromBase64($ciphertext));
echo "<br><br><br>";
echo "Verification: " . ($crypter->verifyByPublic($publickey, $plaintext,$signed) ? 'valid' : 'invalid');