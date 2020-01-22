
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
  4. First configure the VLAN taging pre-requesist such as 
      1. Add Bridge Domain
      2. Add a new EPG
      3. Add a new physical domain to EPG binding
      4. Add a new VLAN pool
      5. Add a new VLAN encap block
  5. Deploy Static Path binding for given EPG.
  6. After successfull completion of above step update artifacts to change ticekt close the change ticket.

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

**Sample playbook Output:**

*
```
PLAY [Usecases for ACI VLAN taging] ********************************************
TASK [aci_config_snapshot : Create a Snapshot] *********************************
changed: [localhost]
TASK [aci_vlan_tag : Deploy Static Path binding for given EPG] *****************
skipping..
TASK [aci_vlan_tag : Add Bridge Domain] ****************************************
changed: [localhost -> localhost]
TASK [aci_vlan_tag : Add a new EPG] ********************************************
changed: [localhost -> localhost]
TASK [aci_vlan_tag : Add a new physical domain to EPG binding] *****************
changed: [localhost -> localhost]
TASK [aci_vlan_tag : Add a new VLAN pool] **************************************
changed: [localhost -> localhost]
TASK [aci_vlan_tag : Add a new VLAN encap block] *******************************
changed: [localhost -> localhost]
TASK [aci_vlan_tag : Deploy Static Path binding for given EPG] *****************
changed: [localhost -> localhost] => (item=['1/37', 55])
changed: [localhost -> localhost] => (item=['1/38', 55])
changed: [localhost -> localhost] => (item=['1/39', 55])
TASK [snow_update : Get specific Static Path binding for given EPG] ************
ok: [localhost -> localhost] => (item=1/37)
ok: [localhost -> localhost] => (item=1/38)
ok: [localhost -> localhost] => (item=1/39)
TASK [snow_update : SNOW work log Update] **************************************
changed: [localhost] => (item={'changed': False, 'current': [{'fvRsPathAtt': {'attributes': {'annotation': '', 'childAction': '', 'descr': '', 'dn': 'uni/tn-LAX/ap-LAX-APN/epg-db_epg/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/37]]', 'encap': 'vlan-55', 'extMngdBy': '', 'forceResolve': 'yes', 'instrImedcy': 'immediate', 'lcC': '', 'lcOwn': 'local', 'modTs': '2020-01-20T13:23:00.189+00:00', 'mode': 'regular', 'monPolDn': 'uni/tn-common/monepg-default', 'primaryEncap': 'unknown', 'rType': 'mo', 'state': 'unformed', 'stateQual': 'none', 'status': '', 'tCl': 'fabricPathEp', 'tDn': 'topology/pod-1/paths-101/pathep-[eth1/37]', 'tType': 'mo', 'uid': '15374'}}}], 'invocation': {'module_args': {'host': '198.18.133.200', 'username': 'admin', 'password': 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER', 'tenant': 'LAX', 'ap': 'LAX-APN', 'epg': 'db_epg', 'interface_type': 'switch_port', 'pod_id': 1, 'leafs': ['101'], 'interface': '1/37', 'state': 'query', 'use_ssl': False, 'validate_certs': False, 'timeout': 300, 'outp…
changed: [localhost] => (item={'changed': False, 'current': [{'fvRsPathAtt': {'attributes': {'annotation': '', 'childAction': '', 'descr': '', 'dn': 'uni/tn-LAX/ap-LAX-APN/epg-db_epg/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/38]]', 'encap': 'vlan-55', 'extMngdBy': '', 'forceResolve': 'yes', 'instrImedcy': 'immediate', 'lcC': '', 'lcOwn': 'local', 'modTs': '2020-01-20T13:23:03.597+00:00', 'mode': 'regular', 'monPolDn': 'uni/tn-common/monepg-default', 'primaryEncap': 'unknown', 'rType': 'mo', 'state': 'unformed', 'stateQual': 'none', 'status': '', 'tCl': 'fabricPathEp', 'tDn': 'topology/pod-1/paths-101/pathep-[eth1/38]', 'tType': 'mo', 'uid': '15374'}}}], 'invocation': {'module_args': {'host': '198.18.133.200', 'username': 'admin', 'password': 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER', 'tenant': 'LAX', 'ap': 'LAX-APN', 'epg': 'db_epg', 'interface_type': 'switch_port', 'pod_id': 1, 'leafs': ['101'], 'interface': '1/38', 'state': 'query', 'use_ssl': False, 'validate_certs': False, 'timeout': 300, 'outp…
changed: [localhost] => (item={'changed': False, 'current': [{'fvRsPathAtt': {'attributes': {'annotation': '', 'childAction': '', 'descr': '', 'dn': 'uni/tn-LAX/ap-LAX-APN/epg-db_epg/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/39]]', 'encap': 'vlan-55', 'extMngdBy': '', 'forceResolve': 'yes', 'instrImedcy': 'immediate', 'lcC': '', 'lcOwn': 'local', 'modTs': '2020-01-20T13:23:07.018+00:00', 'mode': 'regular', 'monPolDn': 'uni/tn-common/monepg-default', 'primaryEncap': 'unknown', 'rType': 'mo', 'state': 'unformed', 'stateQual': 'none', 'status': '', 'tCl': 'fabricPathEp', 'tDn': 'topology/pod-1/paths-101/pathep-[eth1/39]', 'tType': 'mo', 'uid': '15374'}}}], 'invocation': {'module_args': {'host': '198.18.133.200', 'username': 'admin', 'password': 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER', 'tenant': 'LAX', 'ap': 'LAX-APN', 'epg': 'db_epg', 'interface_type': 'switch_port', 'pod_id': 1, 'leafs': ['101'], 'interface': '1/39', 'state': 'query', 'use_ssl': False, 'validate_certs': False, 'timeout': 300, 'outp…
TASK [snow_update : SNOW ticket status changing] *******************************
changed: [localhost] => (item=0)
changed: [localhost] => (item=3)
PLAY RECAP *********************************************************************
localhost                  : ok=9    changed=10    unreachable=0    failed=1    skipped=1    rescued=1    ignored=0   
```

