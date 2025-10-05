import mysql.connector
from mysql.connector import Error
import os

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
    "Filter Rules Allow Packets To A Destination Range": "Medium",
    "Filter Rules Allow Packets From A Source Range To Network Destinations And A Port Range": "Medium",
    "Configuration Backup Missing Integrity Protection": "Medium",
    "No Inbound ICMP Rate Limiting": "Medium",
    "Filter Rules Allow Packets From Any Source": "Medium",
    "Filter Rules Allow Packets From A Network Source": "Medium",
    "Filter Rules Allow Packets From A Source Range": "Medium",
    "Filter Rules Allow Packets To Any Port": "Medium",
    "Filter Rules Allow Packets To A Port Range": "Medium",
    "Filter Rules Allow Packets": "Medium",
    "Weak Syslog Message Integrity Protection": "Medium",
    "Filter Rules Are Configured To Allow FTP Data Connection To High Ports": "Medium",
    "Syslog Logging Destination Configuration Options": "Low",
    "Clear-Text Web HTTP Protocol Enabled": "High",
    "Administration Line Without Password Authentication": "Critical",
    "Syslog Server Destination Is Same As DNS Server": "Low",
    "Default SNMP Community Strings Were Configured": "Critical",
    "Shared Admin And Enable Authentication Passwords": "High",
    "SNMP Community String Appears To Be A Default": "Critical",
    "SNMP Community String Appears To Be Weak": "High",
    "Weak SNMP Community String Was Configured": "High",
    "Weak Cryptographic Hashing Algorithm Configured": "Medium",
    "Weak SSH Encryption Algorithm Configured": "Medium",
    "Weak Cryptographic Encryption Algorithm Configured": "Medium",
    "Weak SSH Server Key Exchange Algorithm Configured": "Medium",
    "SSH Key Exchange Sequence": "Low",
    "DNS Response Message Security Options": "Low",
    "DNS Request Message Integrity Options": "Low",
    "SNMP User Password Appears To Be Weak": "Medium",
    "Weak SNMPv3 User Authentication": "Medium",
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
    "Long Exec Administrative Line Timeout Configured": "Low",
    "RADIUS Servers With A Weak Shared Secret": "Medium",
    "AUX Port Not Disabled": "High",
    "NTP Control Queries Were Unrestricted": "High",
    "ICMP Unreachable Messages Were Enabled": "Low",
    "Weak Time Authentication Key": "High",
    "MOP Enabled": "Low",
    "Classless Routing Enabled": "Low",
    "Administration Line Without An ACL Configured": "High",
    "Weak Password Complexity Policy Setting": "Medium",
    "Not All NTP Time Sources Were Authenticated": "Medium",
    "User Account Names Contained \"admin\"": "Low",
}

def setup_database():
    conn = None
    cursor = None
    try:
        # Get MySQL connection parameters from environment or use defaults
        config = {
            'host': os.getenv('MYSQL_HOST', 'localhost'),
            'database': os.getenv('MYSQL_DATABASE', 'vulnerability_db'),
            'user': os.getenv('MYSQL_USER', 'root'),
            'password': os.getenv('MYSQL_PASSWORD', ''),
            'port': int(os.getenv('MYSQL_PORT', 3306))
        }
        
        # First connect without database to create it
        initial_config = config.copy()
        del initial_config['database']
        conn = mysql.connector.connect(**initial_config)
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config['database']}")
        cursor.close()
        conn.close()
        
        # Now connect to the specific database
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                name VARCHAR(500) PRIMARY KEY,
                severity VARCHAR(50)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_vulnerabilities (
                name VARCHAR(500) PRIMARY KEY,
                severity VARCHAR(50)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending (
                name VARCHAR(500) PRIMARY KEY,
                severity VARCHAR(50),
                search_type VARCHAR(50),
                submitted_by VARCHAR(100)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert severity mappings
        for name, severity in SEVERITY_MAP.items():
            cursor.execute('INSERT INTO vulnerabilities (name, severity) VALUES (%s, %s) ON DUPLICATE KEY UPDATE severity=%s', (name, severity, severity))
            cursor.execute('INSERT INTO firewall_vulnerabilities (name, severity) VALUES (%s, %s) ON DUPLICATE KEY UPDATE severity=%s', (name, severity, severity))
        
        conn.commit()
        print("MySQL database setup completed successfully")
        
    except Error as err:
        print(f"Database error: {err}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

if __name__ == "__main__":
    setup_database()
    print("MySQL database `vulnerability_db` has been created and populated.")