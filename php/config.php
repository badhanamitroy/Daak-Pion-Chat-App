<?php
$conn = mysqli_connect("localhost", "root", "","DaakPion");
if(!$conn) {
echo "Connection failed: ". mysqli_connect_error();
}