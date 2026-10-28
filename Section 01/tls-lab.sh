# Run the class's OpenSSL 3.5 from the tls-lab container, on the folder you are in.
# Load it with: source tls-lab.sh   (or add the alias line to ~/.bashrc)
# Windows PowerShell has no aliases with arguments; use the full command from the README instead.
alias tls-lab='docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work tls-lab'
