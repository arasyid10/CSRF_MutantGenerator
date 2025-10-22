<?
 /*
================

1) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputToLabelHtmlTagMutator [ID] a6a2dabe5c84e411a961b43f253584cf

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<label type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


2) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputToSelectHtmlTagMutator [ID] b040ab2c68ec1764179e283ebbc58b2f

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<select type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


3) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputToButtonHtmlTagMutator [ID] 107b99e8191f4c6738e2584e463ff630

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<button type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


4) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputToTextareaHtmlTagMutator [ID] 215049d23dd47347dfb88a4c90745b73

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<textarea type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


5) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputToFieldsetHtmlTagMutator [ID] ef3c94ee75a0aef1c2f31130100a7e43

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<fieldset type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


6) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 0a4e60bae5482267661e1ed529a9601f

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"text\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


7) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 238e13c0b6459044fd985431d81c3613

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"password\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


8) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 2238229abd5b7840130114d6722e6a37

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"checkbox\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)

9) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 06e3161dea4a295517b2a8aabcc5381b

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"radio\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)



10) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] b3dffe93986da95dc7a047e9ca934caa

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"file\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


11) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 0cc0b3043edfc7708c0f6dc51cb1a90e

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"submit\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)

  PHPUnit 10.5.47 by Sebastian Bergmann and contributors.


12) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] d28ca3fca23b238af06b8661e634f133

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"reset\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


13) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 8889b7e119d05454335011efafa31f72

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"button\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


14) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 3a25a8ab22636c51864d55b6df7cd4d0

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"number\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


15) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] cfadb6b503e9a56a46afa2d72927a02e

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"date\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


16) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] 104357ebce695927bdb225a7801fdbfb

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"email\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


17) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:43    [M] App\Mutator\Html\InputHiddenTypeAlternativesMutator [ID] b709edcbecb279a5374875ee0d3cab42

@@ @@
     public function insertHiddenToken()
     {
         //$hidden = "<!--\n--><input type=\"hidden\"" . " name=\"token-csrf\"" . " value=\"" . $_COOKIE["PHPSESSID"] . "\"" . " />";
-        $hidden = "<input type=\"hidden\"" . " name=\"token-csrf\"" . " value=12345" . " />";
+        $hidden = "<input type=\"url\"" . " name=\"token-csrf\"" . " value=12345" . " />";
         return $hidden;
     }
     public function validateCSRFToken($submittedToken)


18) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:61    [M] App\Mutator\Security\StrcmpToEqualityAlternativesMutator [ID] 6c2e6a4f2becd962b23620d070c3b147

@@ @@
         echo "Expected: {$expected}, Submitted: {$submittedToken}\n";
         // Debugging line
         //return hash_equals($expected, $submittedToken);
-        return strcmp($expected, $submittedToken);
+        return strcasecmp($expected, $submittedToken);
     }
     public function getCSRFToken()
     {


19) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:61    [M] App\Mutator\Security\StrcmpToEqualityAlternativesMutator [ID] ce6a20f70edbc42bca9799ad3b8f6c5e

@@ @@
         echo "Expected: {$expected}, Submitted: {$submittedToken}\n";
         // Debugging line
         //return hash_equals($expected, $submittedToken);
-        return strcmp($expected, $submittedToken);
+        return strcoll($expected, $submittedToken);
     }
     public function getCSRFToken()
     {


20) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:61    [M] App\Mutator\Security\StrcmpToEqualityAlternativesMutator [ID] 2594a0c43ffe751d23f4f8833bebe200

@@ @@
         echo "Expected: {$expected}, Submitted: {$submittedToken}\n";
         // Debugging line
         //return hash_equals($expected, $submittedToken);
-        return strcmp($expected, $submittedToken);
+        return levenshtein($expected, $submittedToken);
     }
     public function getCSRFToken()
     {


21) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:68    [M] RandomBytesToOpenSslRandomPseudoBytes [ID] 7328c73e1787b4d5e63a5bf2c51ef176

@@ @@
     {
         $this->unsetToken();
         if (empty($this->session[$this->sessionTokenLabel])) {
-            $this->session[$this->sessionTokenLabel] = bin2hex(random_bytes($this->tokenLen));
+            $this->session[$this->sessionTokenLabel] = bin2hex(openssl_random_pseudo_bytes($this->tokenLen));
         }
         if ($this->hmac_ip !== false) {
             $token = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);


22) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:68    [M] RandomBytesToRandomInt [ID] 6e1bef42866634da060a1eb357f7b402

@@ @@
     {
         $this->unsetToken();
         if (empty($this->session[$this->sessionTokenLabel])) {
-            $this->session[$this->sessionTokenLabel] = bin2hex(random_bytes($this->tokenLen));
+            $this->session[$this->sessionTokenLabel] = bin2hex(random_int(0, $this->tokenLen));
         }
         if ($this->hmac_ip !== false) {
             $token = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);


23) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:68    [M] App\Mutator\RandomBytesToRandMutator [ID] 32773463b9f82677dca82f01441fd83f

@@ @@
     {
         $this->unsetToken();
         if (empty($this->session[$this->sessionTokenLabel])) {
-            $this->session[$this->sessionTokenLabel] = bin2hex(random_bytes($this->tokenLen));
+            $this->session[$this->sessionTokenLabel] = bin2hex(rand(0, $this->tokenLen));
         }
         if ($this->hmac_ip !== false) {
             $token = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);


24) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:88    [M] App\Mutator\Security\HashHmacAlgoAlternativesMutator [ID] 3fdddb2b17253884ab6ef2faf202bc02

@@ @@
         //based on
         //$message = $_COOKIE["PHPSESSID"]. "!" .$token;
         $message = "12345!" . $token;
-        $hashHmac = \hash_hmac($this->hashAlgo, $message, $this->hmacData);
+        $hashHmac = \hash_hmac('Md5', $message, $this->hmacData);
         return $hashHmac;
     }
 }


25) D:\Kegiatanku\S3\Semester 8\PPT\Kelompok 3 IPL\traversal-vulnerabilities-main\traversal-vulnerabilities-main\src\UserProfileRead.php:88    [M] App\Mutator\Security\HashHmacAlgoAlternativesMutator [ID] 8bdd2537674174b7ee6e78595272fcad

@@ @@
         //based on
         //$message = $_COOKIE["PHPSESSID"]. "!" .$token;
         $message = "12345!" . $token;
-        $hashHmac = \hash_hmac($this->hashAlgo, $message, $this->hmacData);
+        $hashHmac = \hash_hmac('Whirlpool', $message, $this->hmacData);
         return $hashHmac;
     }
 }

##Instructions
- Create a security test case capable of killing the mutant in the "##Survived Mutant Code" section above.
*/