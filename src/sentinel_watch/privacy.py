"""Explicit private case folders; never silently collect into a public checkout."""
from pathlib import Path
import base64
import json
import os
import stat
import subprocess


class CaseError(ValueError):
    pass


def _path(path):
    target = Path(os.path.abspath(path))
    for ancestor in (*reversed(target.parents), target):
        if not ancestor.exists():
            continue
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise CaseError('E_CASE_LINK')
    return target


def _windows_acl(path, create=False):
    # Only a filesystem path is embedded. No credential or endpoint is passed.
    quoted = str(path).replace("'", "''")
    body = """$ErrorActionPreference='Stop'
$p='%s'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$item=[IO.DirectoryInfo]::new($p)
%s
$a=if($PSVersionTable.PSEdition -eq 'Core'){[IO.FileSystemAclExtensions]::GetAccessControl($item,[Security.AccessControl.AccessControlSections]::Access)}else{$item.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)}
$r=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if(-not $a.AreAccessRulesProtected -or $r.Count -ne 2){exit 1}
foreach($v in $r){if($v.IdentityReference.Value -notin @($sid.Value,$system.Value) -or $v.AccessControlType -ne 'Allow' -or $v.FileSystemRights -ne 'FullControl'){exit 1}}
exit 0
""" % (quoted, """$a=[Security.AccessControl.DirectorySecurity]::new()
$a.SetAccessRuleProtection($true,$false)
foreach($identity in @($sid,$system)){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
if($PSVersionTable.PSEdition -eq 'Core'){[IO.FileSystemAclExtensions]::SetAccessControl($item,$a)}else{$item.SetAccessControl($a)}""" if create else '')
    encoded = base64.b64encode(body.encode('utf-16le')).decode('ascii')
    try:
        result = subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive',
                                 '-EncodedCommand',encoded],capture_output=True,timeout=20)
        if result.returncode:
            raise CaseError('E_CASE_PERMISSIONS')
    except CaseError:
        raise
    except Exception:
        raise CaseError('E_CASE_PERMISSIONS') from None


def verify_case(path):
    target = _path(path)
    if not target.is_dir():
        raise CaseError('E_CASE_MISSING')
    if os.name == 'nt':
        _windows_acl(target)
    else:
        info = target.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CaseError('E_CASE_PERMISSIONS')
    return target


def init_case(path):
    target = _path(path)
    if not target.exists():
        if not target.parent.is_dir():
            raise CaseError('E_CASE_PARENT')
        target.mkdir(mode=0o700 if os.name != 'nt' else 0o777)
        if os.name == 'nt':
            _windows_acl(target, create=True)
    return verify_case(target)
