
**F5 Volume Utilization Check**

- Version: 1.0
- **Developed By:** Anirudh S Somanchi, Sujish V Sudhakaran

- **url:** https://github.com/Sujishv/Dontaccess/new/master/F5_Volume_Utilization_V6

**Purpose:***

To Check the volume utilization status at the device once the servicenow ticket created and take the necessary actions to reduce the Volume. 

**Device Type:** F5 Load Balancer


**Summary:**

  1. Once the ticket is generated, Service now triggers the automation and sends the required parameters like Device IP, Incident number and Snow instance to our Ansible tower.
  2. Ansible tower activates the playbook by passing the necessary attributes which includes Credentials(Vault), Device IP(service now parameter), Incident Number (service now parameter) and Instance number (service now parameter).
  3. Playbooks Checks the Device Volume details, Health Check and updates the ticket logs with required logs.

**Inputs:**

1. snow_username  # Service Now Username (Stored in vault)
2. snow_password  # Service Now Password (Stored in vault)
3. snow_instance  # Snow Instance    (Variable Input)
4. incident_num  # Incident Number   (Variable Input)
5. ansible_user   # Device Username   (Stored in vault)
6. ansible_password  # Device Password (Stored in vault)
7. Ip 		# Device IP address    (Variable Input)

**Output:**

* Take necessary actions on the device to reduce the volume utilization 
* Volume Utilization Check on the device
* Device Health Check Output 
