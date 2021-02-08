#!/bin/bash

# Global variables
arch="$(uname -m)"
# Edge cases... urgh. There *was* a reason it's like this. It'll get tested further
# later and get cleaned up as required in a later patch.
silent=false
os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
version="$(awk -F '=' '/^VERSION_ID=/ {print $2}' /etc/os-release 2>&-)"
arg=""
errors=""
outputfolder="/usr/share/greatsct-output"
runuser="$(whoami)"
if [ "${os}" == "ubuntu" ] || [ "${os}" == "arch" ] || [ "${os}" == "blackarch" ] || [ "${os}" == "manjaro" ] || [ "${os}" == "debian" ] || [ "${os}" == '"elementary"' ] || [ "${os}" == "deepin" ] || [ "${os}" == "linuxmint" ] ; then
  trueuser="$(who | tr -d '\n' | cut -d' ' -f1)"
else
  trueuser="$(who am i | cut -d' ' -f1)" # If this is blank, we're actually root (kali)
fi

if [ "${runuser}" == "root" ] && [ "${trueuser}" == "" ]; then
  trueuser="root"
fi

if [ "${trueuser}" != "root" ]; then
  userhomedir="$(echo /home/${trueuser})"
else
  userhomedir="${HOME}"
fi
userprimarygroup="$(id -Gn "${trueuser}" | cut -d' ' -f1)"
rootdir=$(cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd)
winedir="$userhomedir/.greatsct"
BOLD="\033[01;01m"     # Highlight
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
RESET="\033[00m"       # Normal

########################################################################
# Title function
func_title(){
  # Echo title
  echo " =========================================================================="
  echo "                  GreatSCT (Setup Script) | [Updated]: 2018-01-21"
  echo " =========================================================================="
  echo "  [Web]: https://github.com/GreatSCT/GreatSCT | [Twitter]: @ConsciousHacker"
  echo " =========================================================================="
  echo ""
  echo "Debug:      userhomedir = ${HOME}"
  echo "Debug:          rootdir = ${rootdir}"
  echo "Debug:         trueuser = ${trueuser}"
  echo "Debug: userprimarygroup = ${userprimarygroup}"
  echo "Debug:               os = ${os}"
  echo "Debug:          version = ${version}"
  echo "Debug:          winedir = ${winedir}"
  echo ""
}

# Trap CTRl-C
function ctrl_c() {
  echo -e "\n\n${RED}Quitting...${RESET}\n"
  exit 2
}

# Environment checks
func_check_env(){
  # Check sudo dependency
  which sudo >/dev/null 2>&-
  if [ "$?" -ne "0" ]; then
    echo ""
    echo -e " ${RED}[ERROR]: This setup script requires sudo!${RESET}"
    echo "          Please install and configure sudo then run this setup again."
    echo "          Example: For Debian/Ubuntu: apt-get -y install sudo"
    echo "                   For Fedora 22+: dnf -y install sudo"
    exit 1
  fi

  # Double check install
  if [ "${os}" != "kali" ] || [ "${os}" == "parrot" ]; then
    echo -e "\n ${BOLD}[!] NON-KALI Users: Before you begin the install, make sure that you have"
    echo -e "     the Metasploit-Framework installed before you proceed!${RESET}\n"
    read -p 'Continue? ([Y]/[n]o): ' installgreatsct
    if [ "${installgreatsct}" == 'n' ] || [ "${installgreatsct}" == 'N' ]; then
      echo -e "\n ${RED}[ERROR]: Installation aborted by user.${RESET}\n"
      exit 1
    fi
  fi

  if [ "${silent}" == "true" ]; then
    echo -e "\n [?] ${BOLD}Are you sure you wish to install GreatSCT?${RESET}\n"
    echo -e "     Continue with installation? ([${BOLD}y${RESET}]/[${GREEN}S${RESET}]ilent/[${BOLD}n${RESET}]o): ${GREEN}S${RESET}"
  else
    echo -e "\n [?] ${BOLD}Are you sure yoau wish to install GreatSCT?${RESET}\n"
    read -p '     Continue with installation? ([y]/[s]ilent/[N]o): ' installgreatsct
    if [ "${installgreatsct}" == 's' ]; then
      silent=true
    elif [ "${installgreatsct}" != 'y' ]; then
      echo -e "\n ${RED}[ERROR]: Installation aborted by user.${RESET}\n"
      exit 1
    fi
  fi

  func_package_deps

  # Finally, update the config
  if [ -f "/etc/greatsct/settings.py" ] && [ -d "${outputfolder}" ]; then
    echo -e "\n\n [*] ${YELLOW}Setttings already detected... Skipping...${RESET}\n"
  else
    func_update_config
  fi
}

# Install architecture dependent dependencies
func_package_deps(){
  echo -e "\n\n [*] ${YELLOW}Initializing package installation${RESET}\n"

  # Begin Wine install for multiple architectures
  # Always install 32-bit support for 64-bit architectures

  # Debian based distributions
  if [ "${os}" == "ubuntu" ] || [ "${os}" == "debian" ] || [ "${os}" == "kali" ] || [ "${os}" == "parrot" ] || [ "${os}" == "deepin" ] || [ "${os}" == "linuxmint" ]; then
    if [ "${silent}" == "true" ]; then
      echo -e "\n\n [*] ${YELLOW}Silent Mode${RESET}: ${GREEN}Enabled${RESET}\n"
      arg=" DEBIAN_FRONTEND=noninteractive"
    fi
  fi

  # Start dependency install
  echo -e "\n\n [*] ${YELLOW}Installing dependencies${RESET}"
  if [ "${os}" == "debian" ] || [ "${os}" == "kali" ] || [ "${os}" == "parrot" ] || [ "${os}" == "ubuntu" ] || [ "${os}" == "deepin" ] || [ "${os}" == "linuxmint" ]; then  
    if [ "${arch}" == "x86_64" ]; then
      echo -e "\n [*] ${YELLOW}Adding x86 architecture to x86_64 system for Wine${RESET}\n"
      sudo ${arg} dpkg --add-architecture i386
      sudo ${arg} apt-get -qq update -y
      sudo ${arg} apt-get -y -qq install mono-complete mono-mcs unzip wget git ruby p7zip wine wine32 wine64 winbind
      func_get_powershell_dll
      func_install_wine_dotnettojscript
    fi

  elif [ "${os}" == '"elementary"' ]; then
    sudo ${arg} apt-get -y install monodevelop mono-mcs unzip wget git ruby

  elif [ "${os}" == "fedora" ] || [ "${os}" == "rhel" ] || [ "${os}" == "centos" ]; then
    sudo ${arg} dnf -y install mingw64-binutils mingw64-cpp mingw64-gcc mingw64-gcc-c++ mono-tools-monodoc monodoc \
      monodevelop mono-tools mono-core wine unzip ruby golang wget git ruby python

  elif [ "${os}" ==  "arch" ] || [ "${os}" == "blackarch" ] || [ "${os}" == "manjaro" ]; then
    sudo pacman -Sy ${arg} --needed mono mono-tools mono-addins wget unzip ruby python ca-certificates \
     base-devel
  fi
  tmp="$?"
  if [ "${tmp}" -ne "0" ]; then
    msg="Failed to install dependencies... Exit code: ${tmp}"
    errors="${errors}\n${msg}"
    echo -e " ${RED}[ERROR] ${msg}${RESET}\n"
  fi

  if [ "${os}" == "kali" ] || [ "${os}" == "parrot" ]; then
    sudo ${arg} apt-get -y install metasploit-framework
    tmp="$?"
    if [ "${tmp}" -ne "0" ]; then
      msg="Failed to install dependencies (Metasploit-Framework)... Exit code: ${tmp}"
      errors="${errors}\n${msg}"
      echo -e " ${RED}[ERROR] ${msg}${RESET}\n"
    fi
  fi
}

# Update GreatSCT config
func_update_config(){
  echo -e "\n [*] ${YELLOW}Updating GreatSCT-Framework configuration...${RESET}\n"
  cd "${rootdir}/config/"

  # SUDOINCEPTION! (There is method behind the, at first glance, madness)
  # The SUDO_USER environment variable of the actual user doesn't get passed on to the python interpreter properly,
  # so when we call "sudo python update.py", it thinks the user calling it, it's interpretation of SUDO_USER is root,
  # and that's not what we want. Look at this fake process tree with what the env variables would be...
  #    - |_ sudo setup.sh (${USER}=root ${SUDO_USER}=yourname)
  #      - | sudo -u yourname sudo python update.py (${USER}=root ${SUDO_USER}=yourname)
  # snip 8<-  -  -  -  -  -  -  -  -  -  -  -  -  - The alternative below without "sudo -u username"...
  #      - | sudo python update.py (${USER}=root ${SUDO_USER}=root)
  # snip 8<-  -  -  -  -  -  -  -  -  -  -  -  -  - And thus it would have screwed up the ${winedir} dir for the user.
  if [ -f /etc/greatsct/settings.py ]; then
    echo -e " [*] ${YELLOW}Detected current GreatSCT-Framework settings file. Removing...${RESET}\n"
    sudo rm -f /etc/greatsct/settings.py
  fi
  sudo -u "${trueuser}" sudo python update.py

  mkdir -p "${outputfolder}"
  mkdir -p "${winedir}"

  # Chown output directory
  if [ -d "${outputfolder}" ]; then
    echo -e "\n [*] ${YELLOW}Ensuring this account (${trueuser}) owns GreatSCT output directory (${outputfolder})...${RESET}"
    sudo chown -R "${trueuser}" "${outputfolder}"
  else
    echo -e " ${RED}[ERROR] Internal Issue. Couldn't create output folder...${RESET}\n"
  fi

  # Ensure that user completely owns the wine directory
  echo -e " [*] ${YELLOW}Ensuring this account (${trueuser}) has correct ownership of ${winedir}${RESET}"
  chown -R "${trueuser}":"${userprimarygroup}" "${winedir}"
}

########################################################################

func_get_powershell_dll(){

  mkdir /tmp/nuget/
  wget https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -O /tmp/nuget/nuget
  chmod +x /tmp/nuget/nuget
  /tmp/nuget/nuget install System.Management.Automation -OutputDirectory /tmp/nuget/
  mkdir /usr/share/powershell/
  cp /tmp/nuget/*/lib/net45/System.Management.Automation.dll /usr/share/powershell/System.Management.Automation.dll
  rm -rf /tmp/nuget

}

func_install_wine_dotnettojscript(){
  mkdir /tmp/greatsct/
  cd /tmp/greatsct
  # I'll move this to a git repo
  wget  https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks
  mv ./winetricks /usr/bin/winetricks
  chmod +x /usr/bin/winetricks
  WINEARCH=win32 WINEPREFIX="$winedir" winecfg
  WINEARCH=win32 WINEPREFIX="$winedir" winetricks -q dotnet35
  mkdir /usr/share/greatsct
  cd /usr/share/greatsct
  wget https://github.com/tyranid/DotNetToJScript/releases/download/v1.0.4/release_v1.0.4.7z
  7z x ./release_v1.0.4.7z
  
}

# Print banner
func_title

# Check architecture
if [ "${arch}" != "x86" ] && [ "${arch}" != "i686" ] && [ "${arch}" != "x86_64" ]; then
  echo -e " ${RED}[ERROR] Your architecture ${arch} is not supported!${RESET}\n\n"
  exit 1
fi

# Check OS
if [ "${os}" == "kali" ]; then
  echo -e " [I] ${YELLOW}Kali Linux ${version} ${arch} detected...${RESET}\n"
elif [ "${os}" == "parrot" ]; then
  echo -e " [I] ${YELLOW}Parrot Security ${version} ${arch} detected...${RESET}\n"
elif [ "${os}" == "ubuntu" ]; then
  version="$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)"
  echo -e " [I] ${YELLOW}Ubuntu ${version} ${arch} detected...${RESET}\n"
elif [ "${os}" == "linuxmint" ]; then
  version="$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)"
  echo -e " [I] ${YELLOW}Linux Mint ${version} ${arch} detected...${RESET}\n"
  if [[ "${version}" -lt "15" ]]; then
    echo -e " ${RED}[ERROR]: GreatSCT is only supported On Ubuntu 15.10 or higher!${RESET}\n"
    exit 1
  fi
elif [ "${os}" == "deepin" ]; then
  version="$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)"
  echo -e " [I] ${YELLOW}Deepin ${version} ${arch} detected...${RESET}\n"
  if [[ "${version}" -lt "15" ]]; then
    echo -e " ${RED}[ERROR]: GreatSCT is only supported On Deepin 15 or higher!${RESET}\n"
    exit 1
  fi
elif [ "${os}" == '"elementary"' ]; then
	echo -e " [I] ${YELLOW}Elementary OS ${version} ${arch} detected...${RESET}\n"
elif [ "${os}" == "debian" ]; then
  version="$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)"
  if [ "${version}" -lt 8 ]; then
    echo -e " ${RED}[ERROR]: ${RED}GreatSCT is only supported on Debian 8 (Jessie) or higher!${RESET}\n"
    exit 1
  fi
elif [ "${os}" == "fedora" ]; then
  echo -e " [I] ${YELLOW}Fedora ${version} ${arch} detected...${RESET}\n"
  if [[ "${version}" -lt "22" ]]; then
    echo -e " ${RED}[ERROR]: GreatSCT is only supported on Fedora 22 or higher!${RESET}\n"
    exit 1
  fi
else
  os="$(awk -F '["=]' '/^ID=/ {print $2}' /etc/os-release 2>&- | cut -d'.' -f1)"
  if [ "${os}" == "arch" ]; then
    echo -e " [I] ${YELLOW}Arch Linux ${arch} detected...${RESET}\n"
  elif [ "${os}" == "blackarch" ]; then
	echo -e " [I] ${RED}BlackArch Linux ${arch} detected...${RESET}\n"
  elif [ "${os}" == "manjaro" ]; then
  	echo -e " [I] ${YELLOW}Manjaro Linux ${arch} detected...${RESET}\n"
  elif [ "${os}" == "debian" ]; then
    echo -e " [!] ${RED}Debian Linux sid/TESTING ${arch} *possibly* detected..."
    echo -e "     If you are not currently running Debian Testing, you should exit this installer!${RESET}\n"
  else
    echo -e " [ERROR] ${RED}Unable to determine OS information. Exiting...${RESET}\n"
    exit 1
  fi
fi

# Trap ctrl-c
trap ctrl_c INT

# Menu case statement
case $1 in
  # Make sure not to nag the user
  -s|--silent)
  silent=true
  func_check_env
  ;;

  # Bypass environment checks (func_check_env) to force install dependencies
  -c|--clean)
  func_package_deps
  func_update_config
  ;;

  # Print help menu
  -h|--help)
  echo ""
  echo "  [Usage]....: ${0} [OPTIONAL]"
  echo "  [Optional].:"
  echo "               -c|--clean    = Force clean install of any dependencies"
  echo "               -s|--silent   = Automates the installation"
  echo "               -h|--help     = Show this help menu"
  echo ""
  exit 0
  ;;

  # Run standard setup
  "")
  func_check_env
  ;;

*)
  echo -e "\n\n ${RED}[ERROR] Unknown option: $1${RESET}\n"
  exit 1
  ;;
esac

if [ "${errors}" != "" ]; then
  echo -e " ${RED} There was issues installing the following:${RESET}\n"
  echo -e " ${BOLD}${errors}${RESET}\n"
fi

file="${rootdir}/setup/setup.sh"

echo -e "\n [I] ${GREEN}Done!${RESET}\n"
exit 0
