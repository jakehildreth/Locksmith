<#
  Prerequisites: PowerShell version 2 or above.
  License: MIT
  Author:  Michael Klement <mklement0@gmail.com>
  DOWNLOAD, from PowerShell version 3 or above:
    irm https://gist.github.com/mklement0/243ea8297e7db0e1c03a67ce4b1e765d/raw/Out-HostColored.ps1 | iex
  The above directly defines the function below in your session and offers guidance for making it available in future
  sessions too.

  Alternatively, download this file manually and dot-source it (e.g.: . /Out-HostColored.ps1)
  To learn what the function does:
    * see the next comment block
    * or, once downloaded, invoke the function with -? or pass its name to Get-Help.

#>

Function Write-HostColorized {
    <#
    .SYNOPSIS
    Colors portions of the default host output that match given patterns.
    .DESCRIPTION
    Colors portions of the default-formatted host output based on either
    regular expressions or literal substrings, assuming the host is a console or
    supports colored output using console colors.
    Matching is restricted to a single line at a time, but coloring multiple
    matches on a given line is supported.
    Two basic syntax forms are supported:
      * Single-color, via -Pattern, -ForegroundColor and -BackgroundColor
      * Multi-color (color per pattern), via a hashtable (dictionary) passed to
        -PatternColorMap.
    Note: Since output is sent to the host rather than the pipeline, you cannot
          chain calls to this function.
    .PARAMETER Pattern
    One or more search patterns specifying what parts of the formatted
    representations of the input objects should be colored.
     * By default, these patterns are interpreted as regular expressions.
     * If -SimpleMatch is also specified, the patterns are interpreted as literal
       substrings.
    .PARAMETER ForegroundColor
    The foreground color to use for the matching portions.
    Defaults to yellow.
    .PARAMETER BackgroundColor
    The optional background color to use for the matching portions.
    .PARAMETER PatternColorMap
    A hashtable (dictionary) with one or more entries in the following format:
      <pattern-or-pattern-array> = <color-spec>
    <pattern-or-pattern-array> is either a single string or an array of strings
    specifying the regex pattern(s) or literal substring(s) (with -SimpleMatch)
    to match.
    NOTE: If you're specifying an array literally, you must enclose it in (...) or
          @(...), and the individual patterns must all be quoted; e.g.:
            @('foo', 'bar')
    <color-spec> is a string that contains either a foreground [ConsoleColor]
    color alone (e.g. 'red'), a combination with a background color separated by ","
    (e.g., 'red,white') or just a background color (e.g, ',white').
    NOTE: If *multiple* patterns stored in a given hashtable may match on a given
          line and you want the *first* matching pattern to "win" predictably, be
          sure to pass an [ordered] hashtable ([ordered] @{ Foo = 'red; ... })
    See the examples for a complete example.
    .PARAMETER CaseSensitive
    Matches the patterns case-sensitively.
    By default, matching is case-insensitive.
    .PARAMETER WholeLine
    Specifies that the entire line containing a match should be colored,
    not just the matching portion.
    .PARAMETER SimpleMatch
    Interprets the -Pattern argument(s) as a literal substrings to match rather
    than as regular expressions.
    .PARAMETER InputObject
    The input object(s) whose formatted representations to color selectively.
    Typically provided via the pipeline.
    .EXAMPLE
    'A fool and his money', 'foo bar' | Out-HostColored foo
    Prints the substring 'foo' in yellow in the two resulting output lines.
    .EXAMPLE
    Get-Date | Out-HostColored '\p{L}+' red white
    Outputs the current date with all tokens composed of letters (p{L}) only in red
    on a white background.
    .EXAMPLE
    Get-Date | Out-HostColored @{ '\p{L}+' = 'red,white' }
    Same as the previous example, only via the dictionary-based -PatternColorMap
    parameter (implied).
    .EXAMPLE
    'It ain''t easy being green.' | Out-HostColored @{ ('easy', 'green') = 'green'; '\bbe.+?\b' = 'black,yellow' }
    Prints the words 'easy' and 'green' in green, and the word 'being' in black on yellow.
    Note the need to enclose pattern array 'easy', 'green' in (...), which also necessitates
    quoting its element.
    .EXAMPLE
    Get-ChildItem | select Name | Out-HostColored -WholeLine -SimpleMatch .txt
    Highlight all text file names in green.
    .EXAMPLE
    'apples', 'kiwi', 'pears' | Out-HostColored '^a', 's$' blue
    Highlight all "A"s at the beginning and "S"s at the end of lines in blue.
    #>

    # === IMPORTANT:
    #   * At least for now, we remain PSv2-COMPATIBLE.
    #   * Thus:
    #     * no `[ordered]`, `::new()`, `[pscustomobject]`, ...
    #     * No implicit Boolean properties in [CmdletBinding()] and [Parameter()] attributes (`Mandatory` instead of just `Mandatory`)
    # ===

    [CmdletBinding(DefaultParameterSetName = 'SingleColor')]
    param(
        [Parameter(ParameterSetName = 'SingleColor', Position = 0, Mandatory)] [string[]] $Pattern,
        [Parameter(ParameterSetName = 'SingleColor', Position = 1)] [ConsoleColor] $ForegroundColor = [ConsoleColor]::Yellow,
        [Parameter(ParameterSetName = 'SingleColor', Position = 2)] [ConsoleColor] $BackgroundColor,
        [Parameter(ParameterSetName = 'PerPatternColor', Position = 0, Mandatory)] [System.Collections.IDictionary] $PatternColorMap,
        [Parameter(ValueFromPipeline = $True)] $InputObject,
        [switch] $WholeLine,
        [switch] $SimpleMatch,
        [switch] $CaseSensitive
    )

    begin {

        Set-StrictMode -Version 1

        if ($PSCmdlet.ParameterSetName -eq 'SingleColor') {

            # Translate the indiv. arguments into the dictionary format suppoorted
            # by -PatternColorMap, so we can process $PatternColorMap uniformly below.
            $PatternColorMap = @{
                $Pattern = $ForegroundColor, $BackgroundColor
            }

        }
        # Otherwise: $PSCmdlet.ParameterSetName -eq 'PerPatternColor', i.e. a dictionary
        #            mapping patterns to colors was directly passed in $PatternColorMap

        try {

            # The options for the [regex] instances to create.
            # We precompile them for better performance with many input objects.
            [System.Text.RegularExpressions.RegexOptions] $reOpts =
            if ($CaseSensitive) { 'Compiled, ExplicitCapture' }
            else { 'Compiled, ExplicitCapture, IgnoreCase' }

            # Transform the dictionary:
            #  * Keys: Consolidate multiple patterns into a single one with alternation and
            #          construct a [regex] instance from it.
            #  * Values: Transform the "[foregroundColor],[backgroundColor]" strings into an arguments
            #            hashtable that can be used for splatting with Write-Host.
            $map = [ordered] @{ } # !! For stable results in repeated enumerations, use [ordered].
            # !! This matters when multiple patterns match on a given line, and also requires the
            # !! *caller* to pass an [ordered] hashtable to -PatternColorMap
            foreach ($entry in $PatternColorMap.GetEnumerator()) {

                # Create a Write-Host color-arguments hashtable for splatting.
                if ($entry.Value -is [array]) {
                    $fg, $bg = $entry.Value # [ConsoleColor[]], from the $PSCmdlet.ParameterSetName -eq 'SingleColor' case.
                } else {
                    $fg, $bg = $entry.Value -split ','
                }
                $colorArgs = @{ }
                if ($fg) { $colorArgs['ForegroundColor'] = [ConsoleColor] $fg }
                if ($bg) { $colorArgs['BackgroundColor'] = [ConsoleColor] $bg }

                # Consolidate the patterns into a single pattern with alternation ('|'),
                # escape the patterns if -SimpleMatch was passsed.
                $re = New-Object regex -Args `
                $(if ($SimpleMatch) {
                  ($entry.Key | ForEach-Object { [regex]::Escape($_) }) -join '|'
                    } else {
                  ($entry.Key | ForEach-Object { '({0})' -f $_ }) -join '|'
                    }),
                $reOpts

                # Add the tansformed entry.
                $map[$re] = $colorArgs

            }
        } catch { throw }

        # Construct the arguments to pass to Out-String.
        $htArgs = @{ Stream = $True }
        if ($PSBoundParameters.ContainsKey('InputObject')) {
            # !! Do not use `$null -eq $InputObject`, because PSv2 doesn't create this variable if the parameter wasn't bound.
            $htArgs.InputObject = $InputObject
        }

        # Construct the script block that is used in the steppable pipeline created
        # further below.
        $scriptCmd = {

            # Format the input objects with Out-String and output the results line
            # by line, then look for matches and color them.
            & $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Out-String', 'Cmdlet') @htArgs | ForEach-Object {

                # Match the input line against all regexes and collect the results.
                $matchInfos = :patternLoop foreach ($entry in $map.GetEnumerator()) {
                    foreach ($m in $entry.Key.Matches($_)) {
                        @{ Index = $m.Index; Text = $m.Value; ColorArgs = $entry.Value }
                        if ($WholeLine) { break patternLoop }
                    }
                }

                # # Activate this for debugging.
                # $matchInfos | Sort-Object { $_.Index } | Out-String | Write-Verbose -vb

                if (-not $matchInfos) {
                    # No match found - output uncolored.
                    Write-Host -NoNewline $_
                } elseif ($WholeLine) {
                    # Whole line should be colored: Use the first match's color
                    $colorArgs = $matchInfos.ColorArgs
                    Write-Host -NoNewline @colorArgs $_
                } else {
                    # Parts of the line must be colored:
                    # Process the matches in ascending order of start position.
                    $offset = 0
                    foreach ($mi in $matchInfos | Sort-Object { $_.Index }) {
                        # !! Use of a script-block parameter is REQUIRED in WinPSv5.1-, because hashtable entries cannot be referred to like properties, unlinke in PSv7+
                        if ($mi.Index -lt $offset) {
                            # Ignore subsequent matches that overlap with previous ones whose colored output was already produced.
                            continue
                        } elseif ($offset -lt $mi.Index) {
                            # Output the part *before* the match uncolored.
                            Write-Host -NoNewline $_.Substring($offset, $mi.Index - $offset)
                        }
                        $offset = $mi.Index + $mi.Text.Length
                        # Output the match at hand colored.
                        $colorArgs = $mi.ColorArgs
                        Write-Host -NoNewline @colorArgs $mi.Text
                    }
                    # Print any remaining part of the line uncolored.
                    if ($offset -lt $_.Length) {
                        Write-Host -NoNewline $_.Substring($offset)
                    }
                }
                Write-Host '' # Terminate the current output line with a newline - this also serves to reset the console's colors on Unix.

            }
        }

        # Create the script block as a *steppable pipeline*, which enables
        # to perform regular streaming pipeline processing, without having to collect
        # everything in memory first.
        $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
        $steppablePipeline.Begin($PSCmdlet)

    } # begin

    process {
        $steppablePipeline.Process($_)
    }

    end {
        $steppablePipeline.End()
    }

}
