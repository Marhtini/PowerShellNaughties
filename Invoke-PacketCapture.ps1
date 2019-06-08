# Packet Capture without TCPDump and Wireshark
# Makes use of the Net Shell 'netsh' command and parameters fed via the CLI
# By @marhtini
# Note: Must be Administrator to run this script
# Found the Knuckles Copy-Pasta @ https://www.reddit.com/r/copypasta/comments/7sausf/ugandan_knuckles_ascii_art/ - I kno da wae
# ETL to CAP conversion method (Credit: https://isc.sans.edu/diary/No+Wireshark%3F+No+TCPDump%3F+No+Problem!/19409)

#TODO: Figure out port filtering, automatic conversion after $maxSize met, NIC specific filtering.

<#
.SYNOPSIS
    A PowerShell Script to execute a packet capture on a target host without the need for TCPDump/Wireshark/&c.
    The "-action stop" parameter will stop the trace, and then convert the .ETL file to .CAP.
    There is an OPSEC tradeoff, as the netsh trace does not run as a seperate process but DOES write the pcap to file.
    If you do not pick an -outFile value, default is %APPDATA%\Local\Temp\NetTraces
.DESCRIPTION
    You used Get-Help! Do you need to know dae wae?
.PARAMETER Path
    The path to the .
.PARAMETER LiteralPath
    Specifies a path to one or more locations. Unlike Path, the value of 
    LiteralPath is used exactly as it is typed. No characters are interpreted 
    as wildcards. If the path includes escape characters, enclose it in single
    quotation marks. Single quotation marks tell Windows PowerShell not to 
    interpret any characters as escape sequences.
.EXAMPLE
    C:\PS> Invoke-PacketCapture.ps1 -action start -outFile C:\temp\capturefile -persistance yes -maxSize 250 
    Start a Packet Capture, write the results to C:\temp\capturefile, allow the capture to persist after reboot, with a maximum size of 250MB

    C:\PS> Invoke-PacketCapture.ps1 -action stop
    Stop the packet capture, convert the .ETL file to .CAP file, and print location to console

    C:\PS> Invoke-PacketCapture.ps1 -action convert -outFile C:\temp\capturefile -convertedFile C:\temp\capturefile_capture
    Converts an ETL file that already exists from ETL to CAP. This is required if you let the packet capture reach maximum size.

.NOTES
    Author: John Martinez @marhtini
    Date:   Feb 12th 2018   
#>

param (
    [string]$action, # Do you want to Start or Stop a trace?
    [string]$ipAddr, # IP Address to Listen Against
    [string]$outFile, # Location of ETL File, Microsoft Network Monitor capture, can be converted to CAP
    [string]$persistance, # Persist after Reboot,
    #[string]$fileMode, # Set to Single to allow for No MaxSize (Defaults Correctly)
    [string]$maxSize, # Max Size in MB
    [string]$convertedFile # location of Converted ETL to CAP
    #[string]$help # "You need help, man." - Everyone, probably. Use Get-Help.
    )

if($action -contains 'convert'){
    
    if ($convertedFile){
        if ($outFile) {
            Write-Host "Converting ETL to Cap, location: " $newCapPath
            Write-Host "This may also take a while, depending on processing power of the system."
            Write-Host "Please be patient :)"

            # Convert to CAP (Credit: https://isc.sans.edu/diary/No+Wireshark%3F+No+TCPDump%3F+No+Problem!/19409)
            $convertedFile = $convertedFile + ".cap"
            $s = New-PefTraceSession -Path $convertedFile -SaveOnStop
            $s | Add-PefMessageProvider -Provider $outFile
            $s | Start-PefTraceSession

            Write-Host "Conversion Complete! Location: " $convertedFile
        }
        else{
            Write-Host "Error: Missing Required Parameter."
            Write-Host "Usage: .\Invoke-PacketCapture.ps1 -action convert -outFile c:\temp\myETLfile -convertedFile c:\temp\desiredFilename"
            exit
        }
    }
    else{
        Write-Host "Error: Missing Required Parameter."
        Write-Host "Usage: .\Invoke-PacketCapture.ps1 -action convert -outFile c:\temp\myETLfile -convertedFile c:\temp\desiredFilename"
        exit
    }
}

if ($action -contains 'stop'){

    Write-Host "Stopping Trace... This may take a while (give it a few minutes)..."
    
    # Get currently running trace's cap path. 
    $stopTracePath = netsh trace show status | Select-String -Pattern "Trace"
    $tpRemoveWhitespace = $stopTracePath -replace '\s',''
    $prePath1 = $tpRemoveWhitespace.split(':')[1] 
    $prePath2 = $tpRemoveWhitespace.split(':')[2]
    $finalPath = $prePath1 + ":" + $prePath2  # WHY? WHY WAS THIS NECESSARY? I wish I had 'cut'.
    $newCapPath = $finalPath + ".cap"
    
    netsh trace stop # Stop Trace

    Write-Host "Converting ETL to Cap, location: " $newCapPath
    Write-Host "This may also take a while, depending on processing power of the system."
    Write-Host "Please be patient :)"

    # Convert to CAP (Credit: https://isc.sans.edu/diary/No+Wireshark%3F+No+TCPDump%3F+No+Problem!/19409)
    $s = New-PefTraceSession -Path $newCapPath -SaveOnStop
    $s | Add-PefMessageProvider -Provider $finalPath
    $s | Start-PefTraceSession

    exit # Bye!
}

elseif ($action -contains 'start'){

    Write-Host "Starting Netsh Trace..."

    $runCommand = 'netsh trace start capture=yes'

    # Set Persistance (Allow to run after reboot)
    if ($persistance -contains "yes"){
        $runCommand = $runCommand + ' persistent=yes'
    }
    elseif ($persistance -contains "no"){
        $runCommand = $runCommand + ' persistent=no'
    }
    elseif (!$persistance) {
        $runCommand = $runCommand + ' persistent=no'
    }
    else{
        Write-Host $persistance 'is not a valid choice. Usage: -persistance <yes|no>'
        Write-Host 'Exiting...'
        exit
    }

    # Set IPv4 Address
    if ($ipAddr){
        if ($ipAddr -as [ipaddress]){ # Valid IP?
            $runCommand = $runCommand + ' Ethernet.Type=IPv4' +' ipv4.address=' + $ipAddr
        }
        else{
            Write-Host $ipAddr 'is not a valid IPv4 Address.'
            Write-Host 'Exiting...'
            exit
        }
    }

    # Set Capture file Location 
    if ($outFile){
        # Set Maximum Size of Capture File (0 = Unlimited)
        if ($maxSize){
            $runCommand = $runCommand + ' traceFile=' + $outFile + '.etl' + ' maxsize=' + $maxSize + ' overwrite=yes'
        }
        else{
            $runCommand = $runCommand + ' traceFile=' + $outFile + '.etl' + ' overwrite=yes'
        }
    }
    
    # Go go go!
    Invoke-Expression $runCommand
    
}

else {
    Write-Host "Error: Please Specify 'start' or 'stop'"
    Write-Host "Usage: Invoke-PacketCapture -action <start|stop|covert>"
}
