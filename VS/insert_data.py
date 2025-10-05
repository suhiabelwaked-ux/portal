import mysql.connector

# Your original vulnerability data dictionary
SEVERITY_MAP = {
    "Rules Allow Access To Administrative Services": "Critical",
    "Filter Rules Allow Packets From Any Source To Any Destination And Any Port": "Critical",
    "Weak SNMP Community Strings Were Configured": "Critical",
    "Filter Rule Allows Packets From Any Source To Any Destination And A Port Range": "High",
    "Filter Rule Allows Packets From Any Source To Network Destinations And Any Port": "High",
    "Rules Allow Access To Clear-Text Protocol Services": "High",
    "Filter Rules Allow Packets From A Network Source To Any Destination And Any Port": "High",
    "Filter Rule Allows Packets From A Source Range To Any Destination And Any Port": "High",
    "Filter Rules Allow Packets From Any Source To A Destination Range And Any Port": "High",
    "User Authentication With no Password": "Critical",
    "Interfaces Were Configured With No Filtering": "Critical",
    "Long Session Timeout": "High",
    "User Account Names Contained": "High",
    "Weak Password Policy Settings": "High",
    "Clear Text Telnet Service Enabled": "High",
    "Clear Text HTTP Service Enabled": "High",
    "Users Configured With Cisco Type 7 Password Hashing": "High",
    "IP Source Routing Was Enabled": "High",
    "Weak Minimum Password Length Policy Setting": "High",
    "SNMP Access With No View": "High",
    "SNMP Access Without Network Filtering": "High",
    "Clear-Text SNMP In Use": "High",
    "Switch Port Security Disabled": "Critical",
    "Rules Allow Access To Potentially Unnecessary Services": "Medium",
    "Rules Allow Access To Potentially Sensitive Services": "Medium",
    "Filter Rules Allow Packets To Any Destination And Any Port": "Medium",
    "Filter Rules Allow Packets From A Source Range To Network Destinations And Any Port": "Medium",
    "Filter Rules Allow Packets From A Network Source To A Destination Range And Any Port": "Medium",
    "Filter Rules Allow Packets From A Network Source To Network Destinations And Any Port": "Medium",
    "Filter Rule Allows Packets From Any Source To Any Destination": "Medium",
    "Filter Rule Allows Packets From Any Source To A Destination Range And A Port Range": "Medium",
    "Filter Rule Allows Packets From Any Source To Network Destinations": "Medium",
    "Filter Rules Allow Packets To Network Destinations And Any Port": "Medium",
    "Filter Rules Allow Packets From A Network Source To A Destination Range And A Port Range": "Medium",
    "Filter Rules Allow Packets From A Source Range To A Destination Range And Any Port": "Medium",
    "Filter Rules Allow Packets From A Network Source To Network Destinations And A Port Range": "Medium",
    "Filter Rule Allows Packets To Any Destination And A Port Range": "Medium",
    "Filter Rules That Allow Any Protocol Were Configured": "Medium",
    "Filter Rules Allow Packets From A Network Source To Any Destination": "Medium",
    "Filter Rules Allow Packets To A Destination Range And Any Port": "Medium",
    "Filter Rules Allow Packets From Any Source To A Destination Range": "Medium",
    "Filter Rule Allows Packets From A Source Range To A Destination Range And A Port Range": "Medium",
    "Filter Rule Allows Packets To Network Destinations And A Port Range": "Medium",
    "Filter Rule Allows Packets From A Source Range To Any Destination": "Medium",
    "No Network Filtering Rules Were Configured": "Critical",
    "Filter Rules Allow Packets To Any Destination": "Medium",
    "Filter Rules Allow Packets From A Network Source To Network Destinations": "Medium",
    "Filter Rules Allow Packets From A Network Source To A Destination Range": "Medium",
    "Filter Rules Allow Packets To A Destination Range And A Port Range": "Medium",
    "Filter Rules Allow Packets From A Source Range To Network Destinations": "Medium",
    "Filter Allow Rules Were Configured Without Any UTM Features": "Medium",
    "Filter Rules Allow Packets To Network Destinations": "Medium",
    "Filter Rules Allow Packets From A Source Range To A Destination Range": "Medium",
    "No BGP Route Flap Prevention": "Medium",
    "No Time Synchronization Configured": "Medium",
    "SNMPv3 User Configured With No Authentication or Privacy": "High",
    "SNMPv3 User Configured With No Privacy": "High",
    "STP BPDU Guard Not Enabled Globally": "High",
    "STP Root Guard Not Enabled": "Medium",
    "No VTP Authentication Password Was Configured": "Medium",
    "Enable Password Configured": "High",
    "DTP Was Enabled": "High",
    "STP Loop Guard Not Enabled": "Medium",
    "Users Configured With Cisco Type 5 Password Hashing": "Medium",
    "No HTTP Service Network Access Restrictions": "High",
    "No SNMP TFTP Server Access List Configured": "Medium",
    "Proxy ARP Was Enabled": "High",
    "Unrestricted Outbound Administrative Access": "High",
    "Switch Port Trunking Allows All VLANs": "High",
    "No Pre-Logon Banner Message": "Low",
    "Syslog Logging Not Enabled": "Medium",
    "Filter Rule List Does Not End With Drop All And Log": "Low",
    "Filter Rules Allow Packets From A Network Source": "Low",
    "Filter Rules Allow Packets To A Destination Range": "Low",
    "Weak SNMPv3 User Privacy Encryption Algorithm Configured": "Low",
    "Weak SNMPv3 User Authentication Hashing Algorithm Configured": "Low",
    "Weak Syslog Severity Level Configured": "Medium",
    "ICMP Redirect Messages Were Enabled": "Low",
    "No Inbound TCP Connection Keep-Alives": "Low",
    "No Outbound TCP Connection Keep-Alives": "Low",
    "CDP Was Enabled": "Medium",
    "The BOOTP Service Was Not Disabled": "Medium",
    "VTP Was In Server Mode": "High",
    "DNS Lookups Were Enabled": "Low",
    "No Post Logon Banner Message": "Low",
    "Filter Allow Rules Were Configured Without Logging": "Medium",
    "No Exec Administrative Line Timeout Configured": "Medium",
    "Long Exec Administrative Line Timeout Configured":"Low",
    "RADIUS Servers With A Weak Shared Secret":"Medium",
    "AUX Port Not Disabled":"High",
    "NTP Control Queries Were Unrestricted":"High",
    "ICMP Unreachable Messages Were Enabled":"Low",
    "Weak Time Authentication Key":"High",
    "MOP Enabled":"Low",
    "Classless Routing Enabled":"Low",
    "Administration Line Without An ACL Configured":"High",
    "Weak Password Complexity Policy Setting":"Medium",
    "Not All NTP Time Sources Were Authenticated":"Medium",
    "User Account Names Contained \"admin\"":"Low",
}

# MySQL connection details
DB_CONFIG = {
    'user': 'root',
    'password': 'admin_2025', 
    'host': 'localhost',
    'database': 'vulnerability_db'
}

def insert_data_to_mysql():
    """Connects to MySQL and inserts all vulnerability data from the dictionary."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        insert_query = "INSERT INTO vulnerabilities (name, severity) VALUES (%s, %s)"

        print("Inserting data into the database...")
        for name, severity in SEVERITY_MAP.items():
            try:
                cursor.execute(insert_query, (name, severity))
            except mysql.connector.Error as err:
                # Handle duplicate entries
                if err.errno == mysql.connector.errorcode.ER_DUP_ENTRY:
                    print(f"Skipping duplicate entry for '{name}'")
                else:
                    print(f"Error inserting data: {err}")
        
        conn.commit()
        print("Data insertion complete.")

    except mysql.connector.Error as err:
        print(f"Failed to connect to MySQL database: {err}")
        print("Please ensure MySQL server is running and connection details are correct.")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    insert_data_to_mysql()