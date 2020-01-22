
**ACI VLAN Tagging**

- Version: 1.0
- **Developed By:** Sujish V Sudhakaran


**Purpose:***

To Tag VLAN on mentioned interfaces. 

**Device Type:** Cisco ACI



**Summary:**

  1. Once the serivce catlog is generated, after flow the change process, Service now triggers the automation and sends the required parameters to Ansible tower/AWX.
  2. Ansible tower lunch the playbook by passing the necessary attributes to extra vars.
  3. Playbook first take the device backup (snapshot )
  4. 
  3. Playbooks Checks the Device Volume details, Health Check and updates the ticket logs with required logs.

**Inputs:**

| Input                | description                    | Example        | Type            |
|----------------------|--------------------------------|----------------|-----------------|
| host                 | IP addess of the APIC          | 198.18.133.200 | extra var input |
| tenant               | Name of the tenant             | LAX            | extra var input |
| pod_id               | pod id                         | 1              | extra var input |
| vrf                  | Name if the VRF                | VRF-LAX        | extra var input |
| ap                   | Name ofthe Application Profile | LAX-APN        | extra var input |
| epg                  | Name of the End Point group    | app_epg        | extra var input |
| bd                   | Name of the Bride Domain       | app_bd         | extra var input |
| domain               | Name of the domain             | app_domain     | extra var input |
| domain_type          | Proide domain type             | phys           | extra var input |
| pool                 | Name of the VLAN POOL          | app_pool       | extra var input |
| pool_allocation_mode | Provide allocation mode        | dynamic        | extra var input |
| encap_id             | vlan number                    | 200            | extra var input |
| interface_mode       | Provide interface mode         | trunk          | extra var input |
| interface_type       | Provide interface type         | port_channel   | extra var input |
| leafs                | provide switch ID              | 101            | extra var input |
| interface            | Interface(s) number            | 1/20           | extra var input |
| block_start          | VLAN pool start number         | 50             | extra var input |
| block_end            | VLAN pool end number           | 60             | extra var input |
| change_number        | Change record number           | CHG0030054     | extra var input |
| username             | Device username                | admin          | Stored in vault |
| password             | Device password                | admin          | Stored in vault |
| snow_instance        | ServiceNow instance            | dev73411       | Stored in vault |
| snow_username        | ServiceNow instance username   | admin          | Stored in vault |
| snow_password        | ServiceNow instance password   | admin          | Stored in vault |

**Output:**

* 

