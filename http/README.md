# HTTP Client Setup

The `http` binary is an SHS client that communicates with the delegation proxy and SHS daemon. For security, it should run as a dedicated unprivileged user.

## Setup Instructions

### Linux

**1. Create the `http` user:**
```bash
sudo useradd --system --home /home/http --shell /usr/sbin/nologin http
```

**2. Create the home directory:**
```bash
sudo mkdir -p /home/http
sudo chown http:http /home/http
sudo chmod 700 /home/http
```

**3. Copy the binary to the home directory:**
```bash
sudo cp ./http /home/http/http
sudo chown http:http /home/http/http
sudo chmod 755 /home/http/http
```

**4. Set the setuid bit (allows the binary to run as the `http` user):**
```bash
sudo chmod u+s /home/http/http
```

The binary will create `cookies.sqlite3` in its home directory on first run with appropriate permissions.

---

### macOS

**1. Create the `http` user:**

On macOS, create a system user with a high UID (macOS reserves UIDs < 500 for system use):

```bash
# Find the next available system UID
NEXT_UID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1 | awk '{print $1 + 1}')

# Create the user (requires sudo)
sudo dscl . -create /Users/http
sudo dscl . -create /Users/http UserShell /usr/sbin/nologin
sudo dscl . -create /Users/http RealName "HTTP Client"
sudo dscl . -create /Users/http UniqueID $NEXT_UID
sudo dscl . -create /Users/http PrimaryGroupID 20  # staff group
sudo dscl . -create /Users/http NFSHomeDirectory /Users/http
```

**2. Create the home directory:**
```bash
sudo mkdir -p /Users/http
sudo chown http:staff /Users/http
sudo chmod 700 /Users/http
```

**3. Copy the binary to the home directory:**
```bash
sudo cp ./http /Users/http/http
sudo chown http:staff /Users/http/http
sudo chmod 755 /Users/http/http
```

**4. Set the setuid bit:**
```bash
sudo chmod u+s /Users/http/http
```

The binary will create `cookies.sqlite3` in its home directory on first run with appropriate permissions.

---

## Verification

After setup, verify the permissions:

### Linux
```bash
ls -l /home/http/
stat /home/http/http | grep Access
```

You should see:
- `http` binary owned by `http:http`
- `http` binary with setuid bit set (shows as `rwsr-xr-x`)

### macOS
```bash
ls -l /Users/http/
stat -x /Users/http/http | grep Access
```

Same expectations as Linux, but group is `staff` instead of `http`.

---

## How It Works

1. **Setuid bit:** When the `http` binary is executed, the kernel runs it with the permissions of the binary's owner (`http` user), regardless of who invoked it.
2. **Home directory:** The binary stores cookies and other state in `$HOME` (e.g., `/home/http` or `/Users/http`).
3. **Database auto-creation:** The `cookies.sqlite3` database is created automatically on first invocation with appropriate permissions.
4. **Unprivileged user:** The `http` user has no login shell and cannot execute arbitrary commands, limiting the blast radius if the binary is compromised.

---

## Troubleshooting

**Permission denied when binary runs:**
- Verify the setuid bit is set: `ls -l /home/http/http` should show `s` in the execute position
- On some filesystems (NFS, etc.), setuid may be disabled. Use `mount | grep /home` to check mount options

**Binary doesn't create cookies.sqlite3:**
- Ensure `/home/http/` (or `/Users/http/` on macOS) is writable by the `http` user: `ls -ld /home/http/`
- Check that the directory has mode `700`: `stat /home/http/`
