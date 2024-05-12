rf=`tput setaf 1`							# Set forground color to red
rb=`tput setab 1;tput setaf 0`				# Set background color to red and forground color to black
yt=`tput setaf 3`							# Set forground color to yellow
yb=`tput setab 3;tput setaf 0`				# Set background color to yellow
reset=`tput sgr0`							# Reset forground and background color
gb=`tput setab 2;tput setaf 0`				# Set background color to green and forground color to black
gt=`tput setaf 2`							# Set foreground color to green
su=`tput smul`    							# Start underline mode
eu=`tput rmul`    							# End underline mode
gray=$(tput setaf 8)
purple=$(tput setaf 5)
pink=$(tput setaf 13)



#yb="\e[43;30m"
#green="\e[32m"
#reset="\e[0m"


# ==============================================================================
# Function to list all applications on the Android device
#

list_installed_packages() {
	
	# # Clear the screen 
	clear

    # Check if installed_packages.log already exists
    if [ -f installed_packages.log ]; then
        echo -e "\n${rb}File installed_packages.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}installed_packages.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv installed_packages.log installed_packages.old
                echo -e "\nExisting ${yt}installed_packages.log${reset} moved to ${gt}installed_packages.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
				clear  
                ;;
            *)
                echo -e "\nFile ${yt}installed_packages.log${reset} not moved."
                ;;
        esac
    fi





	# Listing all applications on the device
	packages=$(adb shell pm list packages -f | sed 's/.*=//' | sort)

	# Printing the list of packages
	echo -e "${yb}List of all applications on the device:${reset}"
	echo -e "--------------------------------------------------\n"
	echo "$packages" | awk '{ print $1 }' | tee -a installed_packages.log

	# Adding a pause
	echo -e "\n${yb}Press any key to continue...${reset}"
	read -n1 -r
	clear
	}



# ==============================================================================
# Function to calculate MD5 checksum for all installed apps
#

calculate_md5sum_pull() {

	# Check if md5sum_pull.log exists
	if [ -f md5sum_pull.log ]; then
		echo -e "\n${rb}File md5sum_pull.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}md5sum_pull.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv md5sum_pull.log md5sum_pull.old
                echo -e "\nExisting ${yt}md5sum_pull.log${reset} moved to ${gt}md5sum_pull.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
                ;;
            *)
                echo -e "\nFile ${yt}md5sum_pull.log${reset} not moved."
                ;;
        esac
	fi



    # Create a temporary directory
    temp_dir=$(mktemp -d)
    date=$(date +"%d%m%Y")
    
    clear
    echo -e "\n${yt}Calculate MD5 checksum for all installed apps${reset}"
    echo -e "--------------------------------------------------\n"
    # Listing all applications on the device
    packages=$(adb shell pm list packages -f | sed 's/.*=//' | sort)
    
    # Loop through each package and calculate MD5 checksum
    for package in $packages; do
        # Pull the app to the temporary directory
        path=$(adb shell pm path "$package" | awk -F':' '{print $2}')
        dest=$temp_dir/"$package"
        
        # Test
        #adb pull $path $dest && echo -e "* Pull of ${yt}$package ${gt}done${reset}" || echo -e "${rb}Fail${reset} to pull ${yt}$package${reset}"
        if adb pull "$path" "$dest" >/dev/null 2>&1; then
        	
        	# Get the md5sum
        	md5=$(md5sum "$dest" | awk '{ print $1 }')
        	
        	# Print package name and MD5 checksum
        	echo -e "${yt}Package:${reset} $package ${gt}MD5:${reset} $md5" | tee -a md5sum_pull.log
        else
        	echo -e "${rb}Fail${reset} to pull ${yt}$package${reset}"
        fi
    done
    
    # Clean up temporary directory
    rm -r "$temp_dir"
    
    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear
}

# ==============================================================================
# Function to calculate MD5 checksum for all installed apps
#

calculate_md5sum_phone() {
	clear

	# Check if md5sum_phone.log exists
	if [ -f md5sum_phone.log ]; then
		echo -e "\n${rb}File md5sum_phone.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}md5sum_phone.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv md5sum_phone.log md5sum_phone.old
                echo -e "\nExisting ${yt}md5sum_phone.log${reset} moved to ${gt}md5sum_phone.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
                ;;
            *)
                echo -e "\nFile ${yt}md5sum_phone.log${reset} not moved."
                ;;
        esac
	fi

    
    clear
    echo -e "\n${yt}Calculate MD5 checksum for all installed apps${reset}"
    echo -e "--------------------------------------------------\n"
    # Listing all applications on the device
    packages=$(adb shell pm list packages -f | sed 's/.*=//' | sort)
    
    # Loop through each package and calculate MD5 checksum
    for package in $packages; do
        # Pull the app to the temporary directory
        path=$(adb shell pm path "$package" | awk -F':' '{print $2}')
        md5=$(adb shell md5sum $path  | awk -F' ' '{print $1}')
        
       	echo -e "${yt}Package:${reset} $package ${gt}MD5:${reset} $md5" | tee -a md5sum_phone.log

    done
    
    
    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear
}

# ==============================================================================
# Snoop on processes
# 

pspy_mob() {
    # Clear the screen
    clear
 
 	# Check if pspy.log exists
	if [ -f pspy.log ]; then
		echo -e "\n${rb}File pspy.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}pspy.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv pspy.log pspy.old
                echo -e "\nExisting ${yt}pspy.log${reset} moved to ${gt}pspy.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
				clear  
                ;;
            *)
                echo -e "\nFile ${yt}pspy.log${reset} not moved."
                ;;
        esac
	fi   

    # Display headline
    clear
    echo -e "${yb}Monitoring processes. Press any key to exit.${reset}"
    
    # Set IFS to newline to handle spaces in process names correctly
    IFS=$'\n'
    
    # Get the initial process list
    old_process=$(adb shell ps -A)
    
    # Loop indefinitely
    while :
    do
        # Get the current process list
        new_process=$(adb shell ps -A)
        
        # Compare old and new process lists and display differences
        diff <(echo "$old_process") <(echo "$new_process") | grep '[<>]' | grep -v "kworker\|ps\|adb" | tee -a pspy.log
        
        # Check for user input with a timeout of 0.2 seconds
        read -t 0.2 -n 1 key
        if [ $? -eq 0 ]; then
            # User input detected, exit the function
            clear
            break
        fi
        
        # Update the old process list
        old_process="$new_process"
    done
}

# ==============================================================================
# Check hash with VirusTotal's API.
# 

check_single_hash_with_virustotal() {
    # Clear the screen
    clear

    # Check if the API key file exists
	if [ -f ~/.virustotal_api_key ]; then
		# Read the API key from the file
		YOUR_API_KEY=$(<~/.virustotal_api_key)
	else
		# If the file does not exist, set the API key to empty string
		YOUR_API_KEY=""
	fi
    
    # Check if the API key is empty
    if [ -z "$YOUR_API_KEY" ]; then
        echo -e "${yt}VirusTotal API key is not set.${reset}\n"
        read -rp "Enter your VirusTotal API key: " api_key_input
        if [ -n "$api_key_input" ]; then
            echo "$api_key_input" > ~/.virustotal_api_key
            echo "API key added successfully."
            YOUR_API_KEY="$api_key_input"
        else
            echo "API key not provided. Exiting."
            return 1
        fi
    fi
    
    	echo  # Move to the next line
	
    # Prompt the user to enter the MD5 hash
    read -rp "${yt}Enter the MD5 hash to check with VirusTotal: ${reset}" md5

    # Send a request to VirusTotal's API to check the MD5 hash
    #response=$(curl -s "https://www.virustotal.com/vtapi/v2/file/report?apikey=$YOUR_API_KEY&resource=$md5")

    # Send a POST request to VirusTotal's API to check the MD5 hash
    response=$(curl -s --request POST \
      --url 'https://www.virustotal.com/vtapi/v2/file/report' \
      -d apikey=$YOUR_API_KEY \
      -d resource=$md5)

    # Parse and display the response
    positives=$(echo "$response" | jq -r '.positives')
    total=$(echo "$response" | jq -r '.total')
    echo -e "\n${yt}MD5:${reset} $md5"
    echo -e "${yt}Positives:${reset} $positives / $total"
    
    # Adding a pause
    pressed_key=""
    echo -e "\n${yb}Press 'Enter' to view antivirus results, or 'X' to return to the main menu...${reset}"
    read -rsn1 pressed_key
    
    # Check the pressed key
    if [ "$pressed_key" == "" ]; then
        echo -e "\n${yt}Antivirus results:${reset}\n"
        echo "$response" | jq -r '.scans | to_entries[] | "\(.key): \(.value.result)"'
    elif [ "$pressed_key" == "x" ] || [ "$pressed_key" == "X" ]; then
        echo -e "\n${yb}Returning to the main menu...${reset}"
        return
    else
        echo -e "\n${rb}Invalid key pressed.${reset} Returning to the main menu..."
        return
    fi

    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear
}


# ==============================================================================
# Get permissions of all aplications.
# 

get_permissions() {

    # Clear the screen
    clear
	
	# Check if permissions_output.log exists
	if [ -f permissions_output.log ]; then
		echo -e "\n${rb}File permissions_output.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}permissions_output.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv permissions_output.log permissions_output.old
                echo -e "\nExisting ${yt}permissions_output.log${reset} moved to ${gt}permissions_output.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
				clear  
                ;;
            *)
                echo -e "\nFile ${yt}permissions_output.log${reset} not moved."
                ;;
        esac
	fi   
	
	# Check if permissions_output.json exists
	if [ -f permissions_output.json ]; then
		echo -e "\n${rb}File permissions_output.json exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}permissions_output.json.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv permissions_output.json permissions_output.json.old
                echo -e "\nExisting ${yt}permissions_output.json${reset} moved to ${gt}permissions_output.json.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
				clear  
                ;;
            *)
                echo -e "\nFile ${yt}permissions_output.json${reset} not moved."
                ;;
        esac
	fi  
	
    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear  
    
    # Strings to highlight in red and yellow
    red_strings=("INTERNET" "CAMERA" "READ_SMS" "READ_CONTACTS" "READ_CALL_LOG" "READ_EXTERNAL_STORAGE" "READ_MEDIA_IMAGES" "RECORD_AUDIO" "RECORD_BACKGROUND_AUDIO" "CAPTURE_AUDIO_OUTPUT" "WRITE_SECURE_SETTINGS" "DOWNLOAD_WITHOUT_NOTIFICATION" "READ_BLOCKED_NUMBERS" "READ_CALENDAR" "READ_WIFI_CREDENTIAL" "GET_ACCOUNTS" "READ_CLIPBOARD")
	yellow_strings=("BLUETOOTH" "ACCESS_FINE_LOCATION" "ACCESS_BACKGROUND_LOCATION" "ACCESS_WIFI_STATE" "CHANGE_WIFI_STATE" "ACCESS_NETWORK_STATE" "CHANGE_NETWORK_STATE" "QUERY_ALL_PACKAGES" "READ_DEVICE_CONFIG" "ALLOWLIST_BLUETOOTH_DEVICE" "WRITE_SMS" "SEND_SMS" "WRITE_EXTERNAL_STORAGE" "AD_ID")

    # Get list of all installed packages
    packages=$(adb shell pm list packages -f | sed 's/.*=//' | sort)
    
    # Display the loading bar
	num_packages=$(echo "$packages" | wc -l)
    local width=$num_packages
    local progress=0
    local block="."
    local empty_block="—"


    # Output file
    output_file="permissions_output.log"
    output_json="permissions_output.json"

	echo -e "\n${yt}Scanning all packages on mobile. Please be patient... ${reset}"	
	printf "Progress: "
	
    # Loop through each package and get permissions
    for package in $packages; do
    	
    	# Display the loading bar
    	((progress++))
    	printf "%s" "$block"
    	
    	
        # Get permissions for the package
        permissions=$(adb shell "dumpsys package $package | awk '/requested/{p=1;next} /install/{p=0} p' | grep permission" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')

        # Open permissions array
        echo "{\"package\": \"$package\", \"permissions\": [" >> "$output_file"

        # Count the number of permissions
        num_permissions=$(echo "$permissions" | wc -l)

        # Parse and print each permission individually
        while IFS= read -r line; do
            # Loop through red_strings array
            for red_string in "${red_strings[@]}"; do
                # Check if the permission contains a red string
                if [[ "$line" == *"$red_string"* ]]; then
                    # Print the permission with red substring
                    echo "\"${line//$red_string/$(printf '\e[31m%s\e[0m' "$red_string")}\"," >> "$output_file"
                    continue 2  # Continue to the next permission
                fi
            done
            
            # Loop through yellow_strings array
            for yellow_string in "${yellow_strings[@]}"; do
                # Check if the permission contains a red string
                if [[ "$line" == *"$yellow_string"* ]]; then
                    # Print the permission with red substring
                    echo "\"${line//$yellow_string/$(printf '\e[33m%s\e[0m' "$yellow_string")}\"," >> "$output_file"
                    continue 2  # Continue to the next permission
                fi
            done
            
            
            # If the permission doesn't contain any red string, print it normally
            if [[ $num_permissions -gt 1 ]]; then
                echo "\"$line\"," >> "$output_file"
            else
                echo "\"$line\"" >> "$output_file"
            fi
            ((num_permissions--))
        done <<< "$permissions"

        # Close permissions array and package object
        echo "]" >> "$output_file"
        echo "}" >> "$output_file"
    done

	echo ""
    echo "Permissions output saved to $output_file"
    
    # Adding a pause
    echo -e "\n${yb}Press any key to read log file...${reset}"
    read -n1 -r
    clear 
    
    
    cat -v $output_file | sed 's/\^\[\[31m//g; s/\^\[\[33m//g; s/\^\[\[0m//g' > $output_json
    sed -i ':a;N;$!ba;s/,\n\]\n\}/\n\]\}/g' $output_json
    cat $output_file
    
    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear  
    
}

# ==============================================================================
# Function to print deviceInfo
#

print_devInfo() {
	clear
	
	# Check if packages_md5.log exists
	if [ -f device_info.log ]; then
		echo -e "\n${rb}File device_info.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}device_info.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv device_info.log device_info.old
                echo -e "\nExisting ${yt}device_info.log${reset} moved to ${gt}device_info.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
				clear
                ;;
            *)
                echo -e "\nFile ${yt}device_info.log${reset} not moved."
                ;;
        esac
	fi	
	
	echo -e "\n${yb}Device Info${reset}\n" | tee -a device_info.log

    echo "1.  ${yt}Android Version:${reset} $(adb shell getprop ro.build.version.release)" | tee -a device_info.log
    echo "2.  ${yt}Manufacturer:${reset} $(adb shell getprop ro.product.manufacturer)" | tee -a device_info.log
    echo "3.  ${yt}Model:${reset} $(adb shell getprop ro.product.model)" | tee -a device_info.log
    echo "4.  ${yt}Board:${reset} $(adb shell getprop ro.product.board)" | tee -a device_info.log
    echo "5.  ${yt}Build Date:${reset} $(adb shell getprop ro.build.date)" | tee -a device_info.log
    echo "6.  ${yt}Build Date (UTC):${reset} $(adb shell getprop ro.build.date.utc)" | tee -a device_info.log
    echo "7.  ${yt}Build Description:${reset} $(adb shell getprop ro.build.description)" | tee -a device_info.log
    echo "8.  ${yt}Build Display ID:${reset} $(adb shell getprop ro.build.display.id)" | tee -a device_info.log
    echo "9.  ${yt}Build Fingerprint:${reset} $(adb shell getprop ro.build.fingerprint)" | tee -a device_info.log
    echo "10. ${yt}Build Flavor:${reset} $(adb shell getprop ro.build.flavor)" | tee -a device_info.log
    echo "11. ${yt}Build Host:${reset} $(adb shell getprop ro.build.host)" | tee -a device_info.log
    echo "12. ${yt}Build ID:${reset} $(adb shell getprop ro.build.id)" | tee -a device_info.log
    echo "13. ${yt}CPU ID:${reset} $(adb shell getprop ro.boot.cpuid)" | tee -a device_info.log
    echo "14. ${yt}Platform:${reset} $(adb shell getprop ro.board.platform)" | tee -a device_info.log
    echo "15. ${yt}Vendor DLKM Build Fingerprint:${reset} $(adb shell getprop ro.vendor_dlkm.build.fingerprint)" | tee -a device_info.log
    echo "16. ${yt}Serial Number:${reset} $(adb shell getprop ro.serialno)" | tee -a device_info.log

	# Adding a pause
	echo -e "\n${yb}Press any key to continue...${reset}"
	read -n1 -r
	clear	

}

# ==============================================================================
# Function to retrieve install time of all installed apps
#


retrieve_installation_time_all_apps() {
	clear
	
	# Check if packages_md5.log exists
	if [ -f install_time.log ]; then
		echo -e "\n${rb}File install_time.log exists.${reset}"
        echo -e "\nDo you want to move it to ${yt}install_time.old${reset}? (y/n)"
        read -n 1 answer
        echo  # Move to the next line

        # Check user's response
        case $answer in
            y|Y)
                # Move the existing file to installed_packages.old
                mv install_time.log install_time.old
                echo -e "\nExisting ${yt}install_time.log${reset} moved to ${gt}install_time.old${reset}"
                
                # Adding a pause
				echo -e "\n${yb}Press any key to continue...${reset}"
				read -n1 -r
				clear
                ;;
            *)
                echo -e "\nFile ${yt}install_time.log${reset} not moved."
                ;;
        esac
	fi	


    # Get list of installed packages
    packages=$(adb shell pm list packages | cut -d':' -f2)
	
    # Iterate over each package
    for package in $packages; do
        # Execute ADB command to retrieve package information
        output=$(adb shell dumpsys package "$package" | grep 'firstInstallTime\|lastUpdateTime\|versionName')

        # Print app name
        echo -e "\n${yb}App Name: $package${reset}" | tee -a install_time.log

		echo -e "$output" | tee -a install_time.log
		sleep 0.5
    done

    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear
}

# ==============================================================================
# List all packages, check permission and scann package
# 



list_packages() {

	clear
    # Getting a list of all packages and their corresponding application locations
    package_info=$(adb shell pm list packages -f)
    
     # Storing package names and their locations in arrays
    declare -a package_names=()
    declare -a app_locations=()

    while IFS= read -r line; do
        package_name=$(echo "$line" | sed 's/.*=//')
        app_location=$(echo "$line" | sed 's/.*=//;s/[^:]*$//')
        package_names+=("$package_name")
        app_locations+=("$app_location")
    done <<< "$package_info"
    
    echo " "
    echo -e "Start scanning ...."
	echo -e "Bad strings: INTERNET, CAMERA, READ_SMS, READ_CONTACTS, READ_CALL_LOG, READ_EXTERNAL_STORAGE, RECORD_AUDIO}"
	echo -e "            ${rf}----------------------------------------------------------------------------------------------${reset}\n\n"
    
    for ((i=0; i<${#package_names[@]}; i++)); do
		check_permissions ${package_names[$i]}
    
    done
    
    # Adding a pause
    # Add echo statements at the end of the scan
	echo -e "${gt}Scan complete.    ¯\_(ツ)_/¯ ${reset}\n\n"
    echo -e "\n${gt}Press any key to exit...${reset}"
    read -n1 -r
    clear

}


check_permissions() {
    local package="$1"
    local bad_strings=("INTERNET" "CAMERA" "READ_SMS" "READ_CONTACTS" "READ_CALL_LOG" "READ_EXTERNAL_STORAGE" "RECORD_AUDIO")

	# Test !!
	# echo $package
    
    # Get the permissions of the package
    local permissions=$(adb shell "dumpsys package $package | awk '/requested/{p=1;next} /install/{p=0} p' | grep permission" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
    local success=true

    # Check if all bad strings are present in the permissions
    for string in "${bad_strings[@]}"; do
        if ! echo "$permissions" | grep -q "$string"; then
            success=false
            break
        fi
    done

    # Echo success if all bad strings are present in the permissions
    if $success; then
    	#message_len=$(echo "All bad strings found in permissions of package $package" | wc -m )
    	#echo $message_len
    	
        echo -e "\n\nAll bad strings found in permissions of package ${rb}$package${reset}"
        echo -e "${rf}------------------------------------------------${reset}"
        scan_package $package
    fi
    
}


scan_package() {
    local package="$1"
        
	path=$(adb shell pm path "${package_names[$i]}" | awk -F':' '{print $2}')
	package=${package_names[$i]}
	md5=$(adb shell md5sum $path  | awk -F' ' '{print $1}')
	user_id=$(adb shell "dumpsys package $package " | grep userId | sort -u)
	user=$(adb shell "ps -A | grep $package" | awk -F" " '{print $1}' | sort -u | head -n 1)
	pkg=$(adb shell "dumpsys package $package " | grep pkg | grep -v pkgFlags ) 
	dataDir=$(adb shell "dumpsys package $package " | grep dataDir )
	timeStamp=$(adb shell "dumpsys package $package " | grep "timeStamp" )
	firstInstallTime=$(adb shell "dumpsys package $package " | grep "firstInstallTime" )
	lastUpdateTime=$(adb shell "dumpsys package $package " | grep "lastUpdateTime" )
	installerPackageName=$(adb shell "dumpsys package $package " | grep "installerPackageName" )
	processHeader=$(adb shell ps -A | head -n 1)
	processID=$(adb shell ps -A | grep $package | grep .)
	
	serviceA=$(adb shell dumpsys meminfo | awk '/A\ Services/,/Previous/' | grep -v "Previous\|A\ Services" | awk -F" " '{print $2}' | sort -u)
	serviceB=$(adb shell dumpsys meminfo | awk '/B\ Services/,/Cached/' | grep -v "Cached\|B\ Services" | awk -F" " '{print $2}' | sort -u)

	echo -e "[+] ${yt}Package:${reset} $package"
	echo -e " +-- ${yt}Package md5sum:${reset}		      $md5"
	echo -e " +-- ${yt}Package path:${reset}		      $path"
	echo -e " +-- ${yt}Package userId:${reset}		  $user_id"
	echo -e " +-- ${yt}Package user:${reset}		      $user"
	echo -e " +-- ${yt}Package pkg:${reset}		  $pkg"
	echo -e " +-- ${yt}Package dataDir:${reset}		  $dataDir"
	echo -e " +-- ${yt}Package timeStamp:${reset}		  $timeStamp"
	echo -e " +-- ${yt}Package firstInstallTime:${reset}	  $firstInstallTime"
	echo -e " +-- ${yt}Package lastUpdateTime:${reset}	  $lastUpdateTime"
	echo -e " +-- ${yt}Package installerPackageName:${reset}$installerPackageName"
	echo -e " | "
	echo -e " +-- ${yt}$processHeader${reset}"
	if [ -n "$processID" ]; then
		while IFS= read -r line; do
			echo -e " |   ${rf}$line${reset}"
		done <<< "$processID"
	else
		echo -e " |\n |       ${gt}  Application is not in process list  ¯\_(ツ)_/¯  ${reset}"
	fi

			
	# ==========================================================================
	# List of Services from meminfo
	echo -e " | "
	echo -e " | "
	echo -e " +-- ${yt}List of Services from meminfo${reset}"

	adb shell dumpsys meminfo | awk '/B\ Services/,/Cached/' | grep -v "Cached\|B\ Services" | awk -F" " '{print $2}' | sort -u |
	while read -r service; do
		if [ "$service" = "$package" ]; then
			echo -e " |   ${rb}$service${reset}"
		else
			echo -e " |   $service"
		fi
	done

        	
	# ==========================================================================
	# Scan network with netstat and use userid as filter
	echo -e " | "
	echo -e " | "
	echo -e " +-- ${yt}Scan network with netstat and use userid as filter${reset}"
	
	userid_num=$(adb shell "dumpsys package $package" | grep userId |sed 's/ //g' | awk -F"=" '{print $2}')

	adb shell netstat -tenp 2>/dev/null |
	while read -r netstat_line; do
		if [[ "$netstat_line" == *"$userid_num"* ]]; then
			echo -e " |   ${rf}$netstat_line${reset}"
		else
			echo -e " |   $netstat_line"
		fi
	done

        	
 	# ==========================================================================
	# Scan vith virustotal

    
    # Check if the API key file exists
	if [ -f ~/.virustotal_api_key ]; then
		# Read the API key from the file
		YOUR_API_KEY=$(<~/.virustotal_api_key)
	else
		# If the file does not exist, set the API key to empty string
		YOUR_API_KEY=""
	fi
    

    # Check if the API key is empty
    if [ -z "$YOUR_API_KEY" ]; then
        echo -e "${yt}VirusTotal API key is not set.${reset}\n"
        read -rp "Enter your VirusTotal API key: " api_key_input
        if [ -n "$api_key_input" ]; then
            echo "$api_key_input" > ~/.virustotal_api_key
            echo "API key added successfully."
            YOUR_API_KEY="$api_key_input"
        else
            echo "API key not provided. Exiting."
            return 1
        fi
    fi
    
    # Send a POST request to VirusTotal's API to check the MD5 hash
    response=$(curl -s --request POST \
      --url 'https://www.virustotal.com/vtapi/v2/file/report' \
      -d apikey=$YOUR_API_KEY \
      -d resource=$md5)  	
	
	
	# Parse and display the response
	echo -e " | "
	echo -e " | "
	# Check if the "positives" and "total" fields exist in the JSON response
	
	#condition=false
	#if [ "$condition" = true ]; then
	if echo "$response" | jq -e '.positives' >/dev/null && echo "$response" | jq -e '.total' >/dev/null; then
		positives=$(echo "$response" | jq -r '.positives')
		total=$(echo "$response" | jq -r '.total')
        link=$(echo "$response" | jq -r '.permalink')
		echo -e " +-- ${yt}Scan with virustotal${reset}"
		echo -e " |   ${yt}MD5:${reset} $md5"
		# Check if positives are zero
		if [ "$positives" -eq 0 ]; then
			# If positives are zero, print in green foreground text
			echo -e " |   ${yt}Positives:${reset} ${gt}$positives${reset} / $total"
		else
			# Otherwise, print in red foreground text
			echo -e " |   ${yt}Positives:${reset} ${rf}$positives${reset} / $total"
            echo -e " |   ${rb}Please visit the link for more details:${reset} $link"
		fi
	else

	
		# Create a temporary directory
		echo -e " +-- ${yt}Uploading file to virustotal${reset}"
		
        # Pull file and upload to virustotal
        if adb pull "$path" "$package" >/dev/null 2>&1; then
        
        	# Specify the file path
			file_path="$package"

			# Get the size of the file in bytes
			file_size=$(stat -c "%s" "$file_path")

			# Calculate the size in megabytes (MB)
			file_size_mb=$(echo "scale=2; $file_size / 1024 / 1024" | bc)

			# Check if the file size is greater than 32 MB
			if (( $(echo "$file_size_mb > 32" | bc -l) )); then
				echo -e " |\n |       ${gt}File is too big. It can't be uploaded to virustotal    ¯\_(ツ)_/¯  ${reset}"
				
			else
        
		    	# Send a POST request to VirusTotal's API - upload file
				response=$(curl -s -X POST \
				  --url 'https://www.virustotal.com/vtapi/v2/file/scan' \
				  -F apikey=$YOUR_API_KEY \
				  -F file=@$package)
				  
				#echo "Response: $response"
				if echo "$response" | jq -e '.response_code' >/dev/null ; then
					response_md5=$(echo "$response" | jq -r '.md5')
					response_code=$(echo "$response" | jq -r '.response_code')
					response_msg=$(echo "$response" | jq -r '.verbose_msg')
					echo -e " |   ${yt}MD5: ${reset} $response_md5"
					echo -e " |   ${yt}Response Code: ${reset} $response_md5"
					echo -e " |   ${yt}Response msg: ${reset} $response_msg"
                    echo -e " |   ${gt}Upload status successful ...${reset}"
                    echo -e " |   "
                    echo -e " |   "
				else
					echo -e " |\n |       ${rb}Fail to uploaded file  !${reset}"
				fi
				
				  
				# Send a POST request to VirusTotal's API to check the MD5 hash
				response=$(curl -s --request POST \
				  --url 'https://www.virustotal.com/vtapi/v2/file/report' \
				  -d apikey=$YOUR_API_KEY \
				  -d resource=$md5)  

                #echo -e "$response"

				if echo "$response" | jq -e '.positives' >/dev/null && echo "$response" | jq -e '.total' >/dev/null; then
					positives=$(echo "$response" | jq -r '.positives')
					total=$(echo "$response" | jq -r '.total')
                    link=$(echo "$response" | jq -r '.permalink')
					echo -e " +-- ${yt}Scan with virustotal${reset}"
					echo -e " |   ${yt}MD5:${reset} $md5"
					# Check if positives are zero
					if [ "$positives" -eq 0 ]; then
						# If positives are zero, print in green foreground text
						echo -e " |   ${yt}Positives:${reset} ${gt}$positives${reset} / $total"
					else
						# Otherwise, print in red foreground text
						echo -e " |   ${yt}Positives:${reset} ${rf}$positives${reset} / $total"
                        echo -e " |   ${rb}Please visit the link for more details:${reset} $link"

					fi

				fi

			fi
		
        else
        	echo -e "${rb}Fail${reset} to pull ${yt}$package${reset}"
        fi
	fi	
		
		
	echo -e " | "
	echo -e " | "
	echo -e " | "

 	echo -e " +-- ${yt}View top 30 processes by CPU usage.${reset}"
    echo -e " |   ${yt} $(adb shell ps -Af | head -n 1) ${reset}"
    if [ -n "$user" ]; then
		while IFS= read -r line; do
		    # Check if the line contains a specific string, e.g., "your_string"
		    if [[ "$line" == *"$user"* ]]; then
		        # Print the line in yellow text
		        echo -e " |   ${rf}$line${reset}"
		    else
		        # Print the line as it is
		        echo " |   $line"
		    fi
		done < <(adb shell ps -Af | sort -nr -k 3 | head -30)
    else
    	echo -e " |\n |       ${gt}  User variable is empty  ¯\_(ツ)_/¯  ${reset}"
    fi
    
 	echo -e " | "
	echo -e " | "
 
 
 	echo -e " +-- ${yt}View top 30 processes by memory usage.${reset}"
    echo -e " |   ${yt} $(adb shell ps -Af | head -n 1) ${reset}"
    if [ -n "$user" ]; then
		while IFS= read -r line; do
		    # Check if the line contains a specific string, e.g., "your_string"
		    if [[ "$line" == *"$user"* ]]; then
		        # Print the line in yellow text
		        echo -e " |   ${rf}$line${reset}"
		    else
		        # Print the line as it is
		        echo " |   $line"
		    fi
		done < <(adb shell ps -Af | sort -nr -k 4 | head -30)
    else
    	echo -e " |\n |       ${gt}  User variable is empty  ¯\_(ツ)_/¯  ${reset}"
    fi
    
 	echo -e " | "
	echo -e " | "
 
        	
 	# ==========================================================================
 	# App permission
 	
 	 	
	# Strings to highlight in red and yellow
	red_strings=("INTERNET" "CAMERA" "READ_SMS" "READ_CONTACTS" "READ_CALL_LOG" "READ_EXTERNAL_STORAGE" "READ_MEDIA_IMAGES" "RECORD_AUDIO" "RECORD_BACKGROUND_AUDIO" "CAPTURE_AUDIO_OUTPUT" "WRITE_SECURE_SETTINGS" "DOWNLOAD_WITHOUT_NOTIFICATION" "READ_BLOCKED_NUMBERS" "READ_CALENDAR" "READ_WIFI_CREDENTIAL" "GET_ACCOUNTS" "READ_CLIPBOARD")
	yellow_strings=("BLUETOOTH" "ACCESS_FINE_LOCATION" "ACCESS_BACKGROUND_LOCATION" "ACCESS_WIFI_STATE" "CHANGE_WIFI_STATE" "ACCESS_NETWORK_STATE" "CHANGE_NETWORK_STATE" "QUERY_ALL_PACKAGES" "READ_DEVICE_CONFIG" "ALLOWLIST_BLUETOOTH_DEVICE" "WRITE_SMS" "SEND_SMS" "WRITE_EXTERNAL_STORAGE" "AD_ID")
    
    # Get permissions for the package
    permissions=$(adb shell "dumpsys package $package | awk '/requested/{p=1;next} /install/{p=0} p' | grep permission" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
	
	echo -e " +-- ${yt}App permissions: ${reset}"
	
    # Open permissions array
    echo "{\"package\": \"$package\", \"permissions\": ["

    # Count the number of permissions
    num_permissions=$(echo "$permissions" | wc -l)

    # Parse and print each permission individually
    while IFS= read -r line; do
        # Loop through red_strings array
        for red_string in "${red_strings[@]}"; do
        
            # Check if the permission contains a red string
            if [[ "$line" == *"$red_string"* ]]; then
                # Print the permission with red substring
                echo "\"${line//$red_string/$(printf '\e[31m%s\e[0m' "$red_string")}\","
                continue 2  # Continue to the next permission
            fi
		done
        
        # Loop through yellow_strings array
        for yellow_string in "${yellow_strings[@]}"; do
            # Check if the permission contains a red string
            if [[ "$line" == *"$yellow_string"* ]]; then
                # Print the permission with red substring
                echo "\"${line//$yellow_string/$(printf '\e[33m%s\e[0m' "$yellow_string")}\","
                continue 2  # Continue to the next permission
            fi
        done
        
        # If the permission doesn't contain any red string, print it normally
        if [[ $num_permissions -gt 1 ]]; then
            echo "\"$line\","
        else
            echo "\"$line\""
        fi
        ((num_permissions--))
        
	done <<< "$permissions"
        
	# Close permissions array and package object
	echo "] }"


    # Adding a pause
    echo -e "\n${yb}Press any key to continue...${reset}"
    read -n1 -r
    clear
    echo -e "\n\n${yt}Scanning ....${reset}\n\n"

}



# ==============================================================================
# Real-time system resource usage and process activity using the 'top' command.
# 

run_adb_top() {
    # Run 'adb shell top' command
    adb shell top
    
    # Adding a pause for user to exit
    echo -e "\n${yt}Press any key to continue...${reset}"
    read -n1 -r
    clear
}

# ==============================================================================
# View top 30 processes by CPU usage.
# 

adb_ps_cpu() {
	clear
	echo -e "${yt} $(adb shell ps -Af | head -n 1) ${reset}"
    adb shell ps -Af | sort -nr -k 3 | head -30
    
    # Adding a pause for user to exit
    echo -e "\n${yt}Press any key to continue...${reset}"
    read -n1 -r
    clear
}


# ==============================================================================
# View top 30 processes by memory usage.
# 

adb_ps_mem() {
	clear
	echo -e "${yt} $(adb shell ps -Af | head -n 1) ${reset}"
    adb shell ps -Af | sort -nr -k 4 | head -30
    
    # Adding a pause for user to exit
    echo -e "\n${yt}Press any key to continue...${reset}"
    read -n1 -r
    clear
}


# -------------------------------------------------------------

# Function to display the menu
display_menu() {
cat << "EOF"




          .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
    `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HUMAN   `XXP' `9XXXXXXXXXXXP'
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP'`v'`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                     `'      9XXXXXX(   )XXXXXXP      `'
                              XXXX X.`v'.X XXXX
                              XP^X'`b   d'`X^XX
                              X. 9  `   '  P )X
                              `b  `       '  d'


                    [ https://medium.com/@im0nk3yar0und ]


EOF


    echo -e "\n${yb}Menu:${reset}"
    echo "---------------------------------------------------------------------------------------"
    echo -e "0.  ${rf}Scan all apps for suspicious behavior.${reset}"
    echo -e "1.  Lists all packages on the Android device."
    echo -e "2.  Get device information."
    echo -e "3.  Calculates the md5sum for all installed apps (phone md5sum)."
    echo -e "4.  Calculates the md5sum for all installed apps (pull then md5sum)."
    echo -e "5.  ${gray}Get permissions of all aplications.${reset}"
    echo -e "6.  Get aplications instalation time."
    echo -e "7.  ${gt}pspy - Snoop on processes.${reset}"
    echo -e "8.  Real-time system resource usage and process activity using the 'top' command."
    echo -e "9.  ${gt}View top 30 processes by CPU usage.${reset}"
    echo -e "10. ${gt}View top 30 processes by memory usage.${reset}"
    echo -e "11. Check hash with VirusTotal's API."
    echo -e "12. Exits the script."
    echo -en "\nEnter your choice: "
	}



# Main function
main() {
	clear
    while :
    do
        display_menu
        read choice
        
        case $choice in
        	0)   list_packages;;
            1)   list_installed_packages;;
            2)   print_devInfo;;
            3)   calculate_md5sum_phone;;
            4)   calculate_md5sum_pull;;
            5)   get_permissions;;
            6)   retrieve_installation_time_all_apps;;
            7)   pspy_mob;;
            8)   run_adb_top;;
            9)   adb_ps_cpu;;
            10)  adb_ps_mem;;
            11)  check_single_hash_with_virustotal;;
            12) echo "Exiting..."; exit;;
            *)  echo "Invalid choice. Please enter a valid option.";;
        esac
    done
	}

# Calling the main function
main
