<?php
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "OK\n";
}
?>
