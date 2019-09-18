<?php

$conn = new mysqli("localhost", "root", "", "TOBA");
if($conn->connect_error != null){
    die($conn->connect_error);
}