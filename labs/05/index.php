<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="../../favicon.ico">
    <title>Historia Animalium</title>
    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">
    <!-- Custom styles for this template -->
    <link href="css/jumbotron-narrow.css" rel="stylesheet">
    <style>
             body 
             {
                background-image: url("background.jpg");                
                background-repeat: no-repeat;
                background-attachment: fixed;
                background-position: center; 
                background-size: auto;
             }
             #footer {
                   width: 100%;
                   height: 100%;  
                   position: fixed; 
                   bottom: 0px; 
                   left: 0px; 
                }
            div {
                text-align: center
            }
            table {
                margin: 1em auto;
            }
        </style>
  </head>

  <body>
    <div class="container">
      <div class="header clearfix">
        <nav>
          <ul class="nav nav-pills pull-right">
            <li role="presentation" class="active"><a href="#">Home</a></li>
          </ul>
        </nav>
        <h3 class="text-muted">The History of Animals</h3>
      </div>
      <div class="jumbotron">
        <h1>The History of Animals</h1>
        <p>By Aristotle </p>
        <p>Written 350 B.C.E</p>
        <p>Translated by D'Arcy Wentworth Thompson</p>
        <p>The History of Animals has been divided into the following sections: </p>
        <p>
        <div ALIGN="CENTER">
          <table BORDER="0" CELLSPACING="5" CELLPADDING="3">
            <TR VALIGN="TOP">
            <TD ALIGN="LEFT"><A HREF="#history_anim.1.i.html" onMouseOver="window.status='Read Book I'; return true;">Book I</A> &nbsp;<FONT SIZE="-1">[85k]</FONT>
            <br><A HREF="#history_anim.2.ii.html" onMouseOver="window.status='Read Book II'; return true;">Book II</A> &nbsp;<FONT SIZE="-1">[83k]</FONT>
            <br><A HREF="#history_anim.3.iii.html" onMouseOver="window.status='Read Book III'; return true;">Book III</A> &nbsp;<FONT SIZE="-1">[102k]</FONT>
            <br></TD>
            <TD ALIGN="LEFT"><A HREF="#history_anim.4.iv.html" onMouseOver="window.status='Read Book IV'; return true;">Book IV</A> &nbsp;<FONT SIZE="-1">[103k]</FONT>
            <br><A HREF="#history_anim.5.v.html" onMouseOver="window.status='Read Book V'; return true;">Book V</A> &nbsp;<FONT SIZE="-1">[129k]</FONT>
            <br><A HREF="#history_anim.6.vi.html" onMouseOver="window.status='Read Book VI'; return true;">Book VI</A> &nbsp;<FONT SIZE="-1">[140k]</FONT>
            <br></TD>
            <TD ALIGN="LEFT"><A HREF="#history_anim.7.vii.html" onMouseOver="window.status='Read Book VII'; return true;">Book VII</A> &nbsp;<FONT SIZE="-1">[55k]</FONT>
            <br><A HREF="#history_anim.8.viii.html" onMouseOver="window.status='Read Book VIII'; return true;">Book VIII</A> &nbsp;<FONT SIZE="-1">[125k]</FONT>
            <br><A HREF="#history_anim.9.ix.html" onMouseOver="window.status='Read Book IX'; return true;">Book IX</A> <FONT SIZE="-1">[163k]</FONT>
            <br></TD>
            </TR>
          </table>
        </div>
        </p>
        <p><b>Download:</b> A 5.6k text-only version is <a HREF="history_anim.mb.txt" onMouseOver="window.status='Download text-only version'; return true;">available for download</a>.</p>
        <p class="lead">Made on the command line</p>
        <p class="lead">Made with vim and &#x2764;</p>
        <p class="lead">
        <?php
          require_once 'secret.php';
          if (!empty($_SERVER['QUERY_STRING'])) {
            $query = $_SERVER['QUERY_STRING'];
            $string = parse_str($query);
            if (!empty($string['wolve'])) $page = $string['wolve'];
          }
          if ($page === '$_SERVER[REMOTE_ADDR]') {
            if (!empty($string['user'])) {
              $user = $string['user'];
            }
            if (!empty($string['pass'])) {
              $pass = $string['pass'];
            }
            if (!empty($user) && !empty($pass)) {
              $tmp1 = hash('sha256', $user);
              $tmp2 = hash('sha256', $pass);
              $secret = hash('sha512', $tmp1 . $tmp2 . 'dog');
            }
            echo (!empty($secret) && $secret === '5e8586c3355551da6d48a5aa10dd7b85ca93404c0f1a7ead6cd1343f45320b3b') ? $_ : 'no flag here.';
          }
          ?>
        </p>
      </div>
  </body>
</html>