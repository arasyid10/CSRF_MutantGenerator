CSRF
<?
You are a software testing expert using PHP-based mutation testing.
1. The source code is written in PHP.
2. Test execution is performed using PHPUnit.
3. Mutation testing is conducted with Infection.
4. A mutant has survived in the following code:

##Functional Security Function
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

##Survived Mutant Security Test Cases 
 public function testCsrfTokenGeneration() {
        $csrfProtection = new securityService();
        $token = $csrfProtection->getCSRFToken();

        $this->assertNotEmpty($token);
    }


##Mutation operators that generate survived mutants
Operator Random Bytes Function, mutate CSRF token generation algorithm like random_bytes to openssl_random_pseudo_bytes etc
##Survived Mutant Code
public function getCSRFToken()
    {   $this->unsetToken();
        if (empty($this->session[$this->sessionTokenLabel])) {
            $this->session[$this->sessionTokenLabel] = bin2hex(openssl_random_pseudo_bytes($this->tokenLen));
        }
        if ($this->hmac_ip !== false) {
            $token = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);
        } else {
            $token = $this->session[$this->sessionTokenLabel];
        }
        return $token;
    }

public function getCSRFToken()
    {   $this->unsetToken();
        if (empty($this->session[$this->sessionTokenLabel])) {
            $this->session[$this->sessionTokenLabel] = bin2hex(random_int($this->tokenLen));
        }
        if ($this->hmac_ip !== false) {
            $token = $this->hMacWithIp($this->session[$this->sessionTokenLabel]);
        } else {
            $token = $this->session[$this->sessionTokenLabel];
        }
        return $token;
    }

##Instructions
Generate a new PHPUnit test case that explicitly targets this mutant and ensures it fails (i.e., kills the mutant). 
The test should be syntactically valid, use proper assertion methods to solve the problem

##Output format.
- Provide the test case in PHPUnit format with clear comments and proper function naming.
- Logical Justification for Survived Mutant Based on Uncovered Path
- If there are any issues in the source code that require improvement to enhance software security, 
please provide comprehensive source code recommendations.
- Remove all comments, leave just the test case code 
