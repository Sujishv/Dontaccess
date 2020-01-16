from __future__ import absolute_import
import re, time, datetime
import os,sys
import imp
import pickle
from datetime import datetime

def Connectivity(JumpServer, J_USERNAME, J_PASSWORD, ip, D_Username, D_Password, path):
    try:
        PROJECT_PATH = path
        fp = open("/tmp/shared.pkl", "wb")
        i = 1
        pickle.dump(PROJECT_PATH, fp)
        print(PROJECT_PATH)
        sys.path.insert(1, str(PROJECT_PATH) + r'/roles/f5_Volume_Utlilization/packages')
        from Device_Modules import ConnectHandler, redispatch
        JumpServer = re.findall('([\d.]+)', str(JumpServer))
        if len(JumpServer) != 0:
            response_content = ''
            try:
                jumpserver = {"device_type": "terminal_server", "ip": str(JumpServer[0]), "username": J_USERNAME,
                              "password": J_PASSWORD, "global_delay_factor": 3}
                net_connect = ConnectHandler(**jumpserver)
                print(net_connect)
                time.sleep(1)
                print(net_connect.find_prompt())
                print('Execution in progess')
                net_connect.write_channel("ssh -p22 -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-dss  " + str(D_Username) + "@" + ip + '\n')
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
                        net_connect.write_channel(str(D_Password) + '\n')
                        output = net_connect.read_channel()
                        if '>' in output or '#' in output:
                            break
                    if 'ssword' in output:
                        a = 'password entered'
                        net_connect.write_channel(str(D_Password) + '\n')
                        time.sleep(.2)
                        output = net_connect.read_channel()
                        print(output)
                        if '#' in output:
                            val = 'break'
                            break
                    if 'timed out' in output:
                        time.sleep(.5)
                        val = 'break'
                    time.sleep(.5)
                    if '>' in output or '#' in output :
                        val = 'break'
                        break
                    i += 1
                    a = 'Last'
                    if i == 61 or val == 'break':
                        break
            except Exception as e:
                    response_content = str('Issue in Device Connectivity, Manual action is required-\n Issue is '+str(e) )
                    decision = 0
        else:
            jumpserver = {"device_type": 'f5_linux', "ip": str(ip), "username": D_Username,
                          "password": D_Password, "global_delay_factor": 3}
            net_connect = ConnectHandler(**jumpserver)
        print(net_connect)
        try:
            redispatch(net_connect, device_type='f5_linux')
            comm_line = net_connect.read_channel()
            # logging.debug(comm_line)
            response_content = ''
            response_content1 = ''
            clock = net_connect.send_command('tmsh show sys clock')
            # logging.debug(clock)
            clock1 = re.findall('([\d\w0-9: ]+)', str(clock))
            c = str(clock1[1])
            d = str(c).split(' ')
            d.pop(4)
            clock_main = ''
            for i in d:
                clock_main += str(i) + ' '
            print(clock_main)
            date_time_obj_time1 = datetime.datetime.strptime(str(clock_main), '%a %b %d %H:%M:%S %Y ')
            image_details = net_connect.send_command('find /shared/images/ -type f -printf \"\\n%AD %AT %p\" | head -n 11 | sort -k1.8n -k1.1nr -k1\n')
            Log_File = net_connect.send_command('find /var/log/log_files/ -type f -printf \"\\n%AD %AT %p\" | head -n 11 | sort -k1.8n -k1.1nr -k1\n')
            image_file_list = image_details.split('\n')
            image_file_list_main = []
            Log_File_list = Log_File.split('\n')
            Log_File_list_main = []
            for k in image_file_list:
                if 'tmp' in str(k) or len(k) <= 5:
                    print('skip')
                else:
                    print('second')
                    value = str(k).split(' ')
                    image_date = str(value[0]) + ' ' + str(value[1])
                    print(image_date)
                    image_date_comvert = datetime.datetime.strptime(str(image_date), '%m/%d/%y %H:%M:%S.0000000000')
                    Check_Days = image_date_comvert-date_time_obj_time1
                    Days = str(Check_Days).split(' ')[0]
                    # if int(Days) > 30:
                    image_file_list_main.append(value[-1])
            for k in Log_File_list:
                if 'tmp' in str(k) or len(k) <= 5:
                    print('skip')
                else:
                    print('second')
                    value1 = str(k).split(' ')
                    log_date = str(value1[0]) + ' ' + str(value1[1])
                    log_date_comvert = datetime.datetime.strptime(str(log_date), '%m/%d/%y %H:%M:%S.0000000000')
                    Log_Check_Days = log_date_comvert-date_time_obj_time1
                    Days = str(Log_Check_Days).split(' ')[0]
                    # if int(Days) > 30:
                    Log_File_list_main.append(value1[-1])
            Deleted_Image_list = ''
            Deleted_Log_list = ''
            for images in image_file_list_main:
                if len(images) != 0:
                    command = 'rm -rf '+str(images)
                    net_connect.send_command(command)
                    ima = re.findall('\/([A-Za-z0-9.]+)',str(images))
                    Deleted_Image_list += str(ima[-1])+'\n'
                else:
                    print('skipped')
            for logs in Log_File_list_main:
                if len(logs) != 0:
                    command = 'rm -rf '+str(logs)
                    net_connect.send_command(command)
                    lo = re.findall('\/([A-Za-z0-9.]+)', str(logs))
                    Deleted_Log_list += str(lo[-1])+'\n'
                else:
                    print('skipped')
            response_content1 += '\n' + '~' * 100 + '\n'
            response_content1 += '\n' + 'Delted Files list are: ' + '\n'
            response_content1 += str(Deleted_Image_list)+'\n'
            response_content1 += '\n' + '~' * 100 + '\n'
            response_content1 += '\n' + 'Delted Log File list are: ' + '\n'
            response_content1 += str(Deleted_Log_list) + '\n'
            response_content1 += '\n' + '~' * 100 + '\n'
            TMM = net_connect.send_command("tmsh show sys memory | grep 'TMM Memory Used'", delay_factor=5, max_loops=10)
            Other = net_connect.send_command("tmsh show sys memory | grep 'Other Memory Used'", delay_factor=5, max_loops=10)
            Swap = net_connect.send_command("tmsh show sys memory | grep 'Swap Used '", delay_factor=5, max_loops=10)
            TMM_Load = re.findall('[0-9]+ +([0-9]+)', str(TMM))
            Other_Load = re.findall('[0-9]+ +([0-9]+)', str(Other))
            Swap_Load = re.findall('[0-9]+ +([0-9]+)', str(Swap))
            TMM_Vaue = int(TMM_Load[0])
            Other_Vaue = int(Other_Load[0])
            Swap_Vaue = int(Swap_Load[0])
            if TMM_Vaue >= 75 or Other_Vaue >= 75 or Swap_Vaue >= 75:
                print('Utilization is high')
                Status = 'Utilization is high'
                decision = 2
            else:
                Status = 'Utilization is Low'
                decision = 1
            response_content ='\nOptimized the Device as possible\n'+ \
                              '\nUtilization Summary: \n ' + str(Status)+ \
                              '\nDevice Clock : \n' + clock +\
                              '\nUtilization Details:\n' \
                              '\nTMM Value ' +str(TMM_Vaue)+ '%\n'+\
                              '\nOther Value :' + str(Other_Vaue) + '%\n'+\
                              '\nSwap Value: ' + str(Swap_Vaue)+'%\n'\
                              +response_content1
        except Exception as e:
            response_content = str('Issue in Device Connectivity')
            decision = 0
    except Exception as e:
        response_content = str('Issue in Device Connectivity\n Issue is: ')+str(e)
        decision = 0
    return response_content, int(decision)


def main():
    module = AnsibleModule(
        argument_spec=dict(
        IP=dict(required=True),
        user=dict(required=True),
		password=dict(required=True),
		JumpServer=dict(required=True),
        j_username= dict(required= True),
        j_password= dict(required=True),
        path=dict(required=True)
        ),
    )
    IP = module.params['IP']
    Username = module.params['user']
    Password = module.params['password']
    JumpServer = module.params['JumpServer']
    J_Username = module.params['j_username']
    J_Password = module.params['j_password']
    path = module.params['path']
    Result_main, decision = Connectivity(JumpServer,J_Username, J_Password,IP, Username, Password, path)
    if decision == 1:
        module.exit_json(changed=False, msg=Result_main, decision=int(decision))
    else:
        module.exit_json(changed=True, msg=Result_main, decision=int(decision))




from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()