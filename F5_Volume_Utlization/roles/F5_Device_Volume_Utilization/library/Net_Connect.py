from __future__ import absolute_import
import re, time
import os
import logging
import os,sys
import sys
import subprocess
import imp
import pickle
# import __builtin__
import logging
########################################################################################################################
# Connectivity
########################################################################################################################


def Connectivity(J_USERNAME, J_PASSWORD, ip, JumpServer, Interface, DeviceType, path, Type):
    try:
        PROJECT_PATH = path
        fp = open("/tmp/shared.pkl", "wb")
        i = 1
        pickle.dump(PROJECT_PATH, fp)
        print(PROJECT_PATH)
        sys.path.insert(1, str(PROJECT_PATH) + r'/packages/')
        from Device_Modules import ConnectHandler, redispatch
        # a = JumpServer
        JumpServer = re.findall('([\d.]+)', str(JumpServer))
        # JumpServer = ['158.87.22.232','158.87.22.233','158.87.22.202','158.87.22.203']
        # ip = '10.27.73.22'
        if len(JumpServer) != 0:
            device_username = J_USERNAME
            device_password = J_PASSWORD
            response_content = ''
            print(device_username)
            try:
                for jump in JumpServer:
                    try:
                        jumpserver = {"device_type": "terminal_server", "ip": str(jump), "username": J_USERNAME,
                                      "password": J_PASSWORD, "global_delay_factor": 3}
                        net_connect = ConnectHandler(**jumpserver)
                        print(net_connect)
                        time.sleep(1)
                        print(net_connect.find_prompt())
                        print('Execution in progess')
                        net_connect.write_channel("ssh -p22 -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-dss  " + device_username + "@" + ip + '\n')
                        max_loops = 60
                        val = ''
                        i = 1
                        num = ''
                        while i <= max_loops:
                            output = net_connect.read_channel()
                            num += output
                            print(output)
                            if 'yes/no' in output:
                                net_connect.write_channel('yes\n')
                                time.sleep(.5)
                                net_connect.write_channel(device_password + '\n')
                                output = net_connect.read_channel()
                                if '>' in output or '#' in output:
                                    break
                            if 'ssword' in output:
                                print(device_password)
                                a = 'password entered'
                                net_connect.write_channel(device_password + '\n')
                                # print(net_connect.device_password)
                                print('Entered Pasword')
                                time.sleep(.2)
                                output = net_connect.read_channel()
                                print(output)
                                if '#' in output:
                                    val = 'break'
                                    break
                            if 'timed out' in output:
                                print('SSH Connection timed out ')
                                time.sleep(.5)
                                val = 'break'
                            time.sleep(.5)
                            if '>' in output or '#' in output :
                                val = 'break'
                                break
                            i += 1
                            a = 'Last'
                        # print(i)
                        if i == 61 or val == 'break':
                            break
                            # net_connect.disconnect()
                            # net_connect.disconnect()
                    except Exception as e:
                        # print(e)
                        continue
            except Exception as e:
                    response_content = str('Issue in Device Connectivity, Manual action is required-' + str(i))
                    # print(e)
                    decision = 0
        else:
            jumpserver = {"device_type": DeviceType, "ip": str(ip), "username": J_USERNAME,
                          "password": J_PASSWORD, "global_delay_factor": 3}
            net_connect = ConnectHandler(**jumpserver)
        print(net_connect)
        redispatch(net_connect, device_type=DeviceType)
        if Type == 'Health_Diag':
            response_content = ''
            from Commands.f5 import Health_Diag
            commands = Health_Diag()
            for command in commands:
                if 'show' in command or 'run' in command or 'bash' in command:
                    response_content += net_connect.send_command(command)#, delay_factor=5, max_loops=10000)
                else:
                    response_content += command
                response_content += '\n' + '~' * 100 + '\n'
            # print(response_content)
            decision = 1
        elif Type == 'CPU_Utilization':
            # value = net_connect.read_channel()
            value = 'tmos'
            from Commands.f5 import CPU_Utilization, CPU_Utilization_Check
            commands = CPU_Utilization(value)
            # print(commands)
            result = []
            for command in commands:
                if 'show' in command or 'run' in command or 'bash' in command:
                    value = net_connect.send_command(command)#, delay_factor=5, max_loops=10000)
                    result.append(str(value))
                else:
                    print('skip')
            response_content , decision = CPU_Utilization_Check(str(result[0]),str(result[1]))
        elif Type == 'Volume_Utilization':
            # value = net_connect.read_channel()
            value = 'tmos'
            from Commands.f5 import Volume_Utilization, Volume_Utilization_Check
            commands = Volume_Utilization()
            # print(commands)
            result = []
            for command in commands:
                if 'show' in command or 'run' in command or 'bash' in command:
                    value = net_connect.send_command(command)#, delay_factor=5, max_loops=10000)
                    result.append(str(value))
                else:
                    print('skip')
            response_content, decision = Volume_Utilization_Check(str(result[0]), str(result[1]))
    except Exception as e:
        response_content = str('Issue in Device Connectivity')+ str(e) + str(len(JumpServer))
        # print(e)
        decision = 0
    return response_content, int(decision)


def main():
    module = AnsibleModule(
        argument_spec=dict(
        Username=dict(required=True),
		Password=dict(required=True),
		IP=dict(required=True),
		JumpServer=dict(required=True),
        Interface=dict(required=True),
        DeviceType=dict(required=True),
        path=dict(required=True),
        Type=dict(required=True)
        ),
    )
    Username = module.params['Username']
    Password = module.params['Password']
    IP = module.params['IP']
    JumpServer = module.params['JumpServer']
    Interface = module.params['Interface']
    DeviceType = module.params['DeviceType']
    path = module.params['path']
    Type = module.params['Type']
    # logging.basicConfig(filename='./logs/'+IP+DeviceType+'_test.log', level=logging.DEBUG)
    # logger = logging.getLogger("netmiko")
    # sys.path.append(str(path))
    #global DeviceType
    # Result_main, decision = Connectivity(Username, Password, IP, JumpServer, path)
    Result_main, decision = Connectivity(Username, Password, IP, JumpServer,Interface, DeviceType, path, Type)
    # print('final')
    # print(Result_main)
    # print(decision)
    if decision == 1:
        module.exit_json(changed=False, meta=Result_main, decision=int(decision))
    else:
        module.exit_json(changed=True, meta=Result_main, decision=int(decision))
    #print(Result)
    #print(type(Result))




from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()