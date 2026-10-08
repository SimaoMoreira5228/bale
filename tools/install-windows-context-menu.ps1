[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0)]
    [string]$BaleExecutable,
    [switch]$Uninstall
)

$classes = 'HKCU:\Software\Classes'
$fileMenu = Join-Path $classes '*\shell\BaleArchive'
$directoryMenu = Join-Path $classes 'Directory\shell\BaleArchive'
$archiveMenu = Join-Path $classes 'SystemFileAssociations\.bale\shell\BaleArchive'

if ($Uninstall) {
    foreach ($path in @($fileMenu, $directoryMenu, $archiveMenu)) {
        if (Test-Path -LiteralPath $path) {
            if ($PSCmdlet.ShouldProcess($path, 'Remove BALE Explorer menu')) {
                Remove-Item -LiteralPath $path -Recurse -Force
            }
        }
    }
    return
}

if ([string]::IsNullOrWhiteSpace($BaleExecutable)) {
    throw 'Pass the path to bale.exe, or use -Uninstall.'
}

$executable = (Resolve-Path -LiteralPath $BaleExecutable).Path

function Set-Cascade($path, $title) {
    New-Item -LiteralPath $path -Force | Out-Null
    Set-ItemProperty -LiteralPath $path -Name 'MUIVerb' -Value $title | Out-Null
    $subcommands = Join-Path $path 'ExtendedSubCommandsKey\Shell'
    New-Item -LiteralPath $subcommands -Force | Out-Null
    return $subcommands
}

function Set-Verb($root, $name, $title, $arguments) {
    $verb = Join-Path $root $name
    New-Item -LiteralPath $verb -Force | Out-Null
    Set-ItemProperty -LiteralPath $verb -Name 'MUIVerb' -Value $title | Out-Null

    $command = Join-Path $verb 'command'
    New-Item -LiteralPath $command -Force | Out-Null
    Set-Item -LiteralPath $command -Value ('"{0}" {1}' -f $executable, $arguments) | Out-Null
}

if ($PSCmdlet.ShouldProcess($fileMenu, 'Register BALE file menu')) {
    $commands = Set-Cascade $fileMenu 'Create BALE archive'
    Set-Verb $commands 'add' 'Create .bale archive' 'context add "%1"'
}

if ($PSCmdlet.ShouldProcess($directoryMenu, 'Register BALE folder menu')) {
    $commands = Set-Cascade $directoryMenu 'Create BALE archive'
    Set-Verb $commands 'add' 'Create .bale archive' 'context add "%1"'
}

if ($PSCmdlet.ShouldProcess($archiveMenu, 'Register BALE archive menu')) {
    $archiveCommands = Set-Cascade $archiveMenu 'Extract BALE archive'
    Set-Verb $archiveCommands 'extract-here' 'Extract here' 'context extract-here "%1"'
    Set-Verb $archiveCommands 'extract-folder' 'Extract to folder' 'context extract-folder "%1"'
}
