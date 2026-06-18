# ns-exec (Namespace Executor)

A secure Python-based execution wrapper that add AppArmor profiles manually to allow trusted applications to use unprivileged user namespaces on hardened Linux systems (Tested on Kubuntu).

## Environment setup and configuration  

Run the following commands to create the configuration directory and initialize the whitelist database with customized access controls:

```bash
# First you have to configure the guard files

# Create the secure configuration directory

sudo mkdir -p /etc/userns-guard

# Create the whitelist file

sudo touch /etc/userns-guard/whitelist.json

# Add control access instructions (Only root can read and write)

sudo chmod 600 /etc/userns-guard/whitelist.json

sudo chown -R root:root /etc/userns-guard

# Initialize with an empty JSON object

sudo tee /etc/userns-guard/whitelist.json <<EOF

{}

EOF
```

## Script installation

Clone the repository and grant execution permissions:d

```bash
chmod +x ns-exec.py
```

## Safely finding paths and adding applications

To prevent symlink exploitation, you must always register and validate the absolute real path of the real binary. Make sure to install apps from trusted sources.

### Locate the real binary path

Use `realpath` and `which` to resolve any intermediate symbolic links to their definitive disk location:

```bash
# Using google-chrome like example

realpath $(which google-chrome)
```

Copy the response (something like `/opt/google/chrome/google-chrome`) to run this binary later.

### Register the application to the whitelist

Run the script using `sudo` pointing to the resolved real path. The script will automatically compute the SHA-256 hash and prompt you for authorization:

```bash
sudo ./ns-exec.py /opt/google/chrome/google-chrome
```

## Execution

To run any other authorized application with dynamic AppArmor profile meditation and safe privilege degradation back to your standard user:

```bash
sudo ./ns-exec.py real_binary_path [optional_arguments]
```

## Extra: Desktop Shortcut Integration (Application Menu and KRunner)

You can launch authorized applications transparently via KRunner or the KDE Application Menu without manually typing commands in a persistent terminal.
Note that in any case a terminal will be opened (and kept open) to authorize the execution of the binary (and keep the program running).

### Extract the Absolute Working Directory
1. Open your terminal.
2. Navigate to the directory where your `ns-exec` script is stored:
   ```bash
   cd "/home/yos/Downloads/Clases/Seguridad/Proyecto final/ns-exec"
   ```
3. Execute the `pwd` command to obtain the absolute path of the folder:
   ```bash
   pwd
   ```
   You will get something like `/home/User/Downloads/Final Project/ns-exec`
4. **Important Notation Rule:** If the output path contains spaces (e.g., Final Project), you must wrap the script path in double quotes ("...") during the next configuration step.
- If the path does not contain spaces, you can safely omit the quotes.

### Modify the Application shortcut
1. Open the KDE Menu Editor and search your application **or** right-click on the application icon in your application launcher and Click on "Edit Application..." to open the properties window.

2. Navigate to the Application tab and configure the following parameters explicitly:

   - Program: sudo

   - Arguments: "/home/yos/Downloads/Final Project/ns-exec/ns-exec.py" /usr/bin/google-chrome-stable %U 

   - Working directory (optional): /home/User/Downloads/Final Project/ns-exec
(Reference image)

3. In the "Advanced" tab, check the box "Run in terminal"
(Reference image)
