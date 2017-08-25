#!/bin/bash

DPKG="$(sudo fuser /var/lib/dpkg/lock)"
if [ -z "$DPKG" ]; then
	echo "\ndpkg locked"
	echo -n "Removing dpkg cache"

	if [ -e /var/lib/apt/lists/lock ]; then
		sudo rm /var/lib/apt/lists/lock
	fi
	echo -n "."

	if [ -e /var/cache/apt/archives/lock ]; then
		sudo rm /var/cache/apt/archives/lock
	fi
	echo -n "."

	if [ -e /var/lib/dpkg/lock ]; then
		sudo rm /var/lib/dpkg/lock
	fi
	echo -n "."
fi

echo "\ndpkg lock clear\n\n"

echo "Installing ufw, gufw, libpam-cracklib, auditd, bum"
sudo apt-get --assume-yes install ufw gufw libpam-cracklib auditd bum 
echo "Done."

echo "\n\nConfiguring firewall"
sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable
echo "Done."

echo -n "\nConfiguring common-password file."
sudo 	echo "password	requisite			pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
		password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 remember=5 minlen=8
		password	requisite			pam_deny.so
		password	required			pam_permit.so
		password	optional	pam_gnome_keyring.so " > tmp
echo -n "."
sudo cp tmp /etc/pam.d/common-password
echo "."	
sudo rm tmp
echo "Done."

echo -n "\nConfiguring login policies."
sudo echo "MAIL_DIR        /var/mail
		FAILLOG_ENAB		yes
		LOG_UNKFAIL_ENAB	no
		LOG_OK_LOGINS		no
		SYSLOG_SU_ENAB		yes
		SYSLOG_SG_ENAB		yes
		FTMP_FILE	/var/log/btmp
		SU_NAME		su
		HUSHLOGIN_FILE	.hushlogin
		ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
		ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
		TTYGROUP	tty
		TTYPERM		0600
		ERASECHAR	0177
		KILLCHAR	025
		UMASK		022

		PASS_MAX_DAYS	90
		PASS_MIN_DAYS	10
		PASS_WARN_AGE	7
		LOGIN_RETRIES		5
		LOGIN_TIMEOUT		60

		UID_MIN			 1000
		UID_MAX			60000
		GID_MIN			 1000
		GID_MAX			60000
		CHFN_RESTRICT		rwh
		DEFAULT_HOME	yes
		USERGROUPS_ENAB yes
		ENCRYPT_METHOD SHA512" > tmp
echo -n "."
sudo cp tmp /etc/login.defs
echo "."
sudo rm tmp
echo "Done."

echo -n "\nConfiguring common-auth."
sudo echo "auth	[success=1 default=ignore]	pam_unix.so nullok_secure
		auth	requisite			pam_deny.so
		auth	required			pam_permit.so
		auth  	required			pam_tally2.so deny=5 onerr=fail unlock_time=1" > tmp
echo -n "."
sudo cp tmp /etc/pam.d/common-auth
echo "."
sudo rm tmp
echo "Done."

echo -n "\nConfiguring auditing."
sudo echo "log_file = /var/log/audit/audit.log
		log_format = RAW
		log_group = root
		priority_boost = 4
		flush = INCREMENTAL
		freq = 20
		num_logs = 4
		disp_qos = lossy
		dispatcher = /sbin/audispd
		name_format = NONE
		##name = mydomain
		max_log_file = 5 
		max_log_file_action = ROTATE
		space_left = 75
		space_left_action = SYSLOG
		action_mail_acct = root
		admin_space_left = 50
		admin_space_left_action = SUSPEND
		disk_full_action = SUSPEND
		disk_error_action = SUSPEND
		##tcp_listen_port = 
		tcp_listen_queue = 5
		tcp_max_per_addr = 1
		##tcp_client_ports = 1024-65535
		tcp_client_max_idle = 0
		enable_krb5 = no
		krb5_principal = auditd
		##krb5_key_file = /etc/audit/audit.key" > tmp
echo -n "."
sudo cp tmp /etc/audit/auditd.conf
echo "."
sudo rm tmp
echo "Done."

echo -n "\nConfiguring sshd."
sudo echo "# Package generated configuration file
	# See the sshd_config(5) manpage for details

	# What ports, IPs and protocols we listen for
	Port 22
	# Use these options to restrict which interfaces/protocols sshd will bind to
	#ListenAddress ::
	#ListenAddress 0.0.0.0
	Protocol 2
	# HostKeys for protocol version 2
	HostKey /etc/ssh/ssh_host_rsa_key
	HostKey /etc/ssh/ssh_host_dsa_key
	HostKey /etc/ssh/ssh_host_ecdsa_key
	HostKey /etc/ssh/ssh_host_ed25519_key
	#Privilege Separation is turned on for security
	UsePrivilegeSeparation yes

	# Lifetime and size of ephemeral version 1 server key
	KeyRegenerationInterval 3600
	ServerKeyBits 1024

	# Logging
	SyslogFacility AUTH
	LogLevel INFO

	# Authentication:
	LoginGraceTime 120
	PermitRootLogin no
	StrictModes yes

	RSAAuthentication yes
	PubkeyAuthentication yes
	#AuthorizedKeysFile	%h/.ssh/authorized_keys

	# Don't read the user's ~/.rhosts and ~/.shosts files
	IgnoreRhosts yes
	# For this to work you will also need host keys in /etc/ssh_known_hosts
	RhostsRSAAuthentication no
	# similar for protocol version 2
	HostbasedAuthentication no
	# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
	#IgnoreUserKnownHosts yes

	# To enable empty passwords, change to yes (NOT RECOMMENDED)
	PermitEmptyPasswords no

	# Change to yes to enable challenge-response passwords (beware issues with
	# some PAM modules and threads)
	ChallengeResponseAuthentication no

	# Change to no to disable tunnelled clear text passwords
	#PasswordAuthentication yes

	# Kerberos options
	#KerberosAuthentication no
	#KerberosGetAFSToken no
	#KerberosOrLocalPasswd yes
	#KerberosTicketCleanup yes

	# GSSAPI options
	#GSSAPIAuthentication no
	#GSSAPICleanupCredentials yes

	X11Forwarding yes
	X11DisplayOffset 10
	PrintMotd no
	PrintLastLog yes
	TCPKeepAlive yes
	#UseLogin no

	#MaxStartups 10:30:60
	#Banner /etc/issue.net

	# Allow client to pass locale environment variables
	AcceptEnv LANG LC_*

	Subsystem sftp /usr/lib/openssh/sftp-server

	# Set this to 'yes' to enable PAM authentication, account processing,
	# and session processing. If this is enabled, PAM authentication will
	# be allowed through the ChallengeResponseAuthentication and
	# PasswordAuthentication.  Depending on your PAM configuration,
	# PAM authentication via ChallengeResponseAuthentication may bypass
	# the setting of "PermitRootLogin without-password".
	# If you just want the PAM account and session checks to run without
	# PAM authentication, then enable this but set PasswordAuthentication
	# and ChallengeResponseAuthentication to 'no'.
	UsePAM yes" > tmp
echo -n "."
sudo cp tmp /etc/ssh/sshd_config
echo "."
sudo rm tmp
echo "Done."


echo "\n\nSetting audit policies"
sudo auditctl -e 1
echo "Done."
echo "\nRemoving johntheripper"
sudo apt --purge remove john
echo "Done."
echo "\nRemoving vsftpd"
sudo apt --purge remove vsftpd
echo "Done."

echo "\n\nPossible backdoors: "
sudo which nc
sudo which netcat

