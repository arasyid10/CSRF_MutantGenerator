<?php

namespace App;

class UserProfileRead
{
   private $formTokenLabel = 'eg-csrf-token-label';
    private $sessionTokenLabel = 'EG_CSRF_TOKEN_SESS_IDX';
    
    public $tokenLen = 200;
    private $post = [];
    private $session = [];
    
    private $server = [];
    private $excludeUrl = [];
    public $hashAlgo = 'sha256';
    private $hmac_ip = true;

    public $hmacData = 'ABCeNBHVe3kmAqvU2s7yyuJSF2gpxKLC&*#@!$~%';
    
    /*public function getProfileByUserId(string $userId): string
    {
        // ❗ Vulnerable: does not check ownership or session
        $base = __DIR__ . '/../vulnerable_files/users/';
        $path = realpath($base . $userId . '/profile.txt');

        if ($path && str_starts_with($path, realpath($base))) {
            return file_get_contents($path);
        }

        return 'Profile not found or access denied';
    }*/
   
    
    //FUNGSI CSRF
    public function xssafe($data, $encoding = 'UTF-8')
    {
        return htmlspecialchars($data, ENT_QUOTES | ENT_HTML401, $encoding);
    }
    public function insertHiddenToken()
    {
     //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
     $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
  
     return $hidden;
    }
    
    public function validateCSRFToken($submittedToken) {
        $this->session[$this->sessionTokenLabel] = 'EG_CSRF_TOKEN_SESS_IDX';
        if (!isset($this->session[$this->sessionTokenLabel])) {
            // CSRF Token not found
            return false;
        }
        if ($this->hmac_ip !== false) {
            $expected = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);
        } else {
            $expected = $this->session[$this->sessionTokenLabel];
        }
        //return hash_equals($expected, $submittedToken);
        return strcmp($expected, $submittedToken) ; 
    }

  
    public function getCSRFToken()
    {   $this->unsetToken();
        if (empty($this->session[$this->sessionTokenLabel])) {
            $this->session[$this->sessionTokenLabel] = bin2hex(random_bytes($this->tokenLen));
        }
        if ($this->hmac_ip !== false) {
            $token = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);
        } else {
            $token = $this->session[$this->sessionTokenLabel];
        }
        return $token;
    }
    public function unsetToken()
    {
        if (! empty($this->session[$this->sessionTokenLabel])) {
            unset($this->session[$this->sessionTokenLabel]);
        }
    }
     //F2
    public function hMacWithIp($token)//hash_message_authentication_code
    {//based on
        //$message = $_COOKIE["PHPSESSID"]. "!" .$token;
        $message = "12345!" .$token;
        $hashHmac = \hash_hmac($this->hashAlgo, $message , $this->hmacData);
        return $hashHmac;
    }
}
