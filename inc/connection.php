<?php 
function dbconnect()
{
    try {
        $host = 'localhost';
        $dbname = 'projet_reseau';
        $user = 'root';
        $pass = 'root';
        $DBH = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);

        return $DBH;
    } catch (PDOException $e) {
        echo $e->getMessage();
    }
}

?>