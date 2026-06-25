---
external help file: Locksmith-help.xml
Module Name: Locksmith
online version:
schema: 2.0.0
---

# Invoke-Locksmith

## SYNOPSIS
Finds the most common malconfigurations of Active Directory Certificate Services (AD CS).

## SYNTAX

```
Invoke-Locksmith [[-Mode] <Int32>] [[-Scans] <Array>] [[-OutputPath] <String>] [[-Credential] <PSCredential>]
 [<CommonParameters>]
```

## DESCRIPTION
Locksmith uses the Active Directory (AD) PowerShell (PS) module to identify 10 misconfigurations
commonly found in Enterprise mode AD CS installations.

## EXAMPLES

### EXAMPLE 1
```
Invoke-Locksmith -Mode 0 -Scans All -OutputPath 'C:\Temp'
```

Finds all malconfigurations and displays them in the console.

### EXAMPLE 2
```
Invoke-Locksmith -Mode 2 -Scans All -OutputPath 'C:\Temp'
```

Finds all malconfigurations and displays them in the console.
The findings are saved in a CSV file in C:\Temp.

## PARAMETERS

### -Mode
Specifies sets of common script execution modes.

-Mode 0
Finds any malconfigurations and displays them in the console.
No attempt is made to fix identified issues.

-Mode 1
Finds any malconfigurations and displays them in the console.
Displays example PowerShell snippet that can be used to resolve the issue.
No attempt is made to fix identified issues.

-Mode 2
Finds any malconfigurations and writes them to a series of CSV files.
No attempt is made to fix identified issues.

-Mode 3
Finds any malconfigurations and writes them to a series of CSV files.
Creates code snippets to fix each issue and writes them to an environment-specific custom .PS1 file.
No attempt is made to fix identified issues.

-Mode 4
Finds any malconfigurations and creates code snippets to fix each issue.
Attempts to fix all identified issues.
This mode may require high-privileged access.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Scans
Specify which scans you want to run.
Available scans: 'All' or Auditing, ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC8, or 'PromptMe'

-Scans All
Run all scans (default).

-Scans PromptMe
Presents a grid view of the available scan types that can be selected and run them after you click OK.

```yaml
Type: Array
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: All
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputPath
Specify the path where you want to save reports and mitigation scripts.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: $PWD
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The credential to use for working with ADCS.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutBuffer, -OutVariable, -PipelineVariable, -Verbose, -WarningAction, -WarningVariable, and -ProgressAction.  For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. You cannot pipe objects to Invoke-Locksmith.ps1.
## OUTPUTS

### Output types:
### 1. Console display of identified issues.
### 2. Console display of identified issues and their fixes.
### 3. CSV containing all identified issues.
### 4. CSV containing all identified issues and their fixes.
## NOTES
The Windows PowerShell cmdlet Restart-Service requires RunAsAdministrator.

## RELATED LINKS
