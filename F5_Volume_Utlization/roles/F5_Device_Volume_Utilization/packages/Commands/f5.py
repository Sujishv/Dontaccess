from netmiko import ConnectHandler, redispatch, Netmiko
import re
import time
import datetime

#########################################################################################################################
                        #Health Check Details#
#########################################################################################################################
def Health_Diag():
    # try:
        # if DeviceType == 'f5_ltm':
        # redispatch(net_connect, device_type=str(Device_Type))
    commands = ["Version Details : \n",
         "show sys version",
         "\nDevice Uptime:\n",
         "run /util bash -c uptime",
         "\nHardware Details: \n",
         "show /sys hardware",
         "\nSystem Information: \n",
         "show /sys tmm-info",
         "\nMemory Details: \n",
         "run /util bash -c df -h",
         "\nProperties: \n",
         "show /ltm virtual all-properties",
         "show /ltm pool all-properties",
         "show /ltm node all-properties"]
        # new_output = ' '
    #     for command in commands:
    #         if 'show' in command:
    #             new_output += net_connect.send_command(command, delay_factor=5, max_loops=10000)
    #         else:
    #             new_output += command
    #         new_output += '\n' + '~' * 100 + '\n'
    # except Exception as e:
    #     new_output = 'Device'
    return commands
#Health_Diag()
#########################################################################################################################
                        #CPU Details#
#########################################################################################################################

def CPU_Utilization(output1):
    # if DeviceType == 'f5_ltm' or DeviceType == 'f5':
    #     redispatch(net_connect, device_type='f5_ltm')
    #     output1 = net_connect.read_channel()
    if 'tmos' in output1:
        commands = ["show sys clock" ,
                    "show sys cpu | grep Utilization"]
        # clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
        # new_output = net_connect.send_command("show sys cpu | grep Utilization", delay_factor=5, max_loops=10)
    else:
        commands = ["tmsh",
                    "show sys clock",
                    "show sys cpu | grep Utilizaiton"]
        # net_connect.send_command("tmsh", delay_factor=5, max_loops=10)
        # clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
        # new_output = net_connect.send_command("show sys cpu | grep Utilization", delay_factor=5, max_loops=10)
    return commands
def CPU_Utilization_Check(clock, new_output):
    try:
        CPU_Load = re.findall('Utilization\s+[0-9]+\s+[0-9]+\s+([0-9]+)', str(new_output))
        Load = int(CPU_Load[0])
        if Load >= 70:
            print('Utilization is high')
            Status = 'Utilization is high'
            decision = 2
        else:
            Status = 'Utilization is Low'
            decision = 1
        # Details = new_output.encode('ascii', 'ignore')
        # response_content = 'Utilization Summary: ' + Status + '\n Utilization Details:  +' + Details + '%'
        response_content = 'Device Clock :' + str(clock) + '\nUtilization Summary:' + str(Status) + '\n Utilization Details: ' +str(new_output) + '%'
    except Exception as e:
        decision = 1
        return str(e) + 'value is here', str(clock) + str(new_output)
    return response_content, decision
#CPU_Utilization()
#########################################################################################################################
                        #Memory Details#
#########################################################################################################################
def Volume_Utilization():
    commands = ["show sys clock" ,
                "bash -c df -h"]
    return commands

def Volume_Utilization_Check(clock, new_output):
    try:
        CPU_Load = re.findall('([0-9]+)%', str(new_output))
        for load in CPU_Load:
            if int(load) > 80:
                status = 'High'
            else :
                 status1 = 'low'
        if status == 'High':
            Status = 'Utilization is high'
            decision = 2
        else:
            Status = 'Utilization is low'
            decision = 1
        # Details = new_output.encode('ascii', 'ignore')
        # response_content = 'Utilization Summary: ' + Status + '\n Utilization Details:  +' + Details + '%'
        response_content = 'Device Clock :' + str(clock) + '\nUtilization Summary:' + str(Status) + '\n Utilization Details: ' +str(new_output) + '%'
    except Exception as e:
        decision = 1
        return str(e) + 'value is here', str(clock) + str(new_output)
    return response_content, decision

def Memory_Utilization():
    if DeviceType == 'f5_ltm' or DeviceType == 'f5':
        redispatch(net_connect, device_type='f5_ltm')
        output1 = net_connect.read_channel()

        if '(tmos)' in output1:
            clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
            TMM = net_connect.send_command("show sys memory | grep 'TMM Memory Used'", delay_factor=5, max_loops=10)
            Other = net_connect.send_command("show sys memory | grep 'Other Memory Used'", delay_factor=5, max_loops=10)
            Swap = net_connect.send_command("show sys memory | grep 'Swap Used '", delay_factor=5, max_loops=10)
            # decision = 1
        else:
            net_connect.send_command("tmsh", delay_factor=5, max_loops=10)
            clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
            TMM = net_connect.send_command("show sys memory | grep 'TMM Memory Used'", delay_factor=5, max_loops=10)
            Other = net_connect.send_command("show sys memory | grep 'Other Memory Used'", delay_factor=5, max_loops=10)
            Swap = net_connect.send_command("show sys memory | grep 'Swap Used '", delay_factor=5, max_loops=10)
            # decision = 1
        # Details = new_output.encode('ascii','ignore')
        TMM_Load = re.findall('[0-9]+ +([0-9]+)', str(TMM))
        Other_Load = re.findall('[0-9]+ +([0-9]+)', str(Other))
        Swap_Load = re.findall('[0-9]+ +([0-9]+)', str(Swap))
        TMM_Vaue = int(TMM_Load[0])
        Other_Vaue = int(Other_Load[0])
        Swap_Vaue = int(Swap_Load[0])
        if TMM_Vaue >= 70 or Other_Vaue >= 70 or Swap_Vaue >= 70:
            print('Utilization is high')
            Status = 'Utilization is high'
            decision = 2
        else:
            Status = 'Utilization is Low'
            decision = 1
        # Details = new_output.encode('ascii','ignore')
        response_content = 'Device Clock :' + clock + '\nUtilization Summary: \n ' + str(
            Status) + '\nUtilization Details:\n TMM Value ' + str(
            TMM_Vaue) + '%\n Other Value :' + str(Other_Vaue) + '% \n Swap Value: ' + str(Swap_Vaue)

    # response_content ='Device clock :  '+clock+'\nUtilization Summary: \n '+str(Status)+'\n Input load is '+str(Input_Load_percent)+'%\n Output Load is'+str(Output_Load_percent)+'\nUtilization Details:\n +'+str(validate)+'%'
        # print(response_content))
    return response_content, decision

#Memory_Utilization()
#########################################################################################################################
                        #Interface Utilization Details#
#########################################################################################################################

def Interface_Utilization(Interface):
    if DeviceType == 'f5' or DeviceType == 'f5_ltm':
        redispatch(net_connect, device_type='f5_ltm')
        output1 = net_connect.read_channel()
        if '(tmos)' in output1:
            clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
            TMM = net_connect.send_command("show net interface " + Interface, delay_factor=5, max_loops=100)
            decision = 1
        else:
            net_connect.send_command("tmsh", delay_factor=5, max_loops=10)
            clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
            TMM = net_connect.send_command("show net interface " + Interface, delay_factor=5, max_loops=100)
            decision = 1
        # Details = new_output.encode('ascii','ignore')
        response_content = 'Device Clock :' + clock + '\nUtilization Summary: \n ' + str(TMM)
    return response_content, decision
# Interface_Utilization(Interface)

#########################################################################################################################
                        #Interface Down Details#
#########################################################################################################################


def Interface_down(Interface):
    if DeviceType == 'f5_ltm' or DeviceType == 'f5':
        redispatch(net_connect, device_type='f5_ltm')
        output1 = net_connect.read_channel()
        if '(tmos)' in output1:
            new_output = net_connect.send_command("show net interface " + Interface + ' ', delay_factor=5, max_loops=10)
            decision = 1
        else:
            net_connect.send_command("tmsh", delay_factor=5, max_loops=10)
            new_output = net_connect.send_command("show net interface " + Interface + ' ', delay_factor=5, max_loops=10)
            decision = 2
        # Details = new_output.encode('ascii','ignore')
        if 'up' in new_output:
            # print('Processor_percentage is high which is ' + str(Processor_percentage) + ' ')
            Load_percentage_Status = 'Interface status Up -- Details are ' + new_output
            decision = 1
        elif 'down' in new_output:
            Load_percentage_Status = 'Interface status Down -- Detaills are ' + new_output
            decision = 2
        else:
            Load_percentage_Status = 'Interface status unknown -- Please check the device'
            decision = 2
        Details = new_output.encode('ascii', 'ignore')
        response_content = Load_percentage_Status
    return response_content, decision
#Interface_down()


#########################################################################################################################
                                #Hardware_Monitoring
#########################################################################################################################
def Hardware_Monitoring():
    if DeviceType == 'f5_ltm' or DeviceType == 'f5':
        redispatch(net_connect, device_type='f5_ltm')
        output1 = net_connect.read_channel()
        if '(tmos)' in output1:
            clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
            Fan_Status = net_connect.send_command("show /sys hardware | grep 'Chassis Fan Status' -A 5", delay_factor=5,
                                                  max_loops=10)
            Power_Status = net_connect.send_command("show /sys hardware | grep 'Chassis Power' -A 4", delay_factor=5,
                                                    max_loops=10)
            new_output = str(Fan_Status) + '\n\n' + str(Power_Status)
        else:
            net_connect.send_command("tmsh", delay_factor=5, max_loops=10)
            clock = net_connect.send_command("show sys clock ", delay_factor=5, max_loops=100)
            Fan_Status = net_connect.send_command("show /sys hardware | grep 'Chassis Fan Status' -A 5",
                                                  delay_factor=5, max_loops=10)
            Power_Status = net_connect.send_command("show /sys hardware | grep 'Chassis Power' -A 4",
                                                    delay_factor=5, max_loops=10)
            new_output = str(Fan_Status) + '\n\n' + str(Power_Status)
        if 'down' in new_output or 'Down' in new_output or 'error' in new_output or 'Error' in new_output or 'bad' in new_output or 'Bad' in str(
                new_output) or 'FAULTY' in str(new_output) or 'Fail' in str(new_output) or 'fail' in str(
                new_output) or 'Invalid' in str(new_output) or 'invalid' in str(new_output):
            print('Issue in Device end')
            Status = 'Issue in Device end, Manual action required'
            decision = 2
        else:
            Status = 'No issue found'
            decision = 1
        Details = new_output.encode('ascii', 'ignore')
        # response_content = 'Utilization Summary: ' + Status + '\n Utilization Details:  +' + Details + '%'
        response_content = 'Device Clock: ' + str(clock) + '\n Hardware Status: ' + str(
            Status) + '\n Hardware Summary:' + str(new_output)
    return response_content
#Hardware_Monitoring()

#########################################################################################################################
    # Packet Loss
#########################################################################################################################
def Packet_Loss():
    if DeviceType == 'f5':
        try:
            redispatch(net_connect, device_type='f5')
            hostname = net_connect.read_channel()
            if '(tmos)' not in hostname:
                net_connect.send_command('tmsh', delay_factor=5, max_loops=1000)
            # hostname = net_connect.send_command('show run | i hostname')
            devicename = re.findall('@\(([A-Za-z0-9]+)\)',str(hostname))
            Clock = net_connect.send_command("show sys clock", delay_factor=5, max_loops=1000)
            Uptime = net_connect.send_command("run /util bash -c uptime", delay_factor=5, max_loops=1000)
            Last_Config = net_connect.send_command("show run | in Last configuration change", delay_factor=5,max_loops=1000)
            CPU_LOAD = net_connect.send_command("show process cpu | i utilization", delay_factor=5, max_loops=10)
            Memory_Util = net_connect.send_command("show memory statistics", delay_factor=5, max_loops=10)
            uptime_list = re.findall('([0-9]+)', str(Uptime))
            print(uptime_list)
            if int(uptime_list[0]) == 0 and int(uptime_list[1]) == 0 and int(uptime_list[2]) == 0 :
                Uptime_Status = 'NotNormal'
            else:
                Uptime_Status = 'Normal'
            Last_Config_details = re.findall('at ([0-9:A-Za-z ]+) by', str(Last_Config))
            print(Last_Config_details)
            date_time_obj_time = datetime.datetime.strptime(str(Last_Config_details[0]), '%H:%M:%S %Z %a %b %d %Y')
            date_time_obj_time1 = datetime.datetime.strptime(str(Clock), '%H:%M:%S.%f %Z %a %b %d %Y')
            date_time_last_config = date_time_obj_time1-date_time_obj_time
            date_time_last_config_main = str(date_time_last_config).split(' ')
            if int(date_time_last_config_main[0]) >0:
                Last_Config_change = 'Normal'
            else:
                Last_Config_change = 'NotNormal'
            CPU_Load = re.findall('seconds: ([0-9]+)', str(CPU_LOAD))
            Load = int(CPU_Load[0])
            if Load >= 70:
                print('Utilization is high')
                CPU_Status = 'NotNormal'
            else:
                CPU_Status = 'Normal'
            print(CPU_Status)
            Processor = re.findall('Processor +[0-9A-Za-z]+ +([0-9]+) +([0-9]+)', str(Memory_Util))
            Processor_percentage = int(Processor[0][1]) * 100 / int(Processor[0][0])
            Status = ''
            print(Processor_percentage)
            if Processor_percentage >= 70:
                Memory_Load = 'NotNormal'
            else:
                Memory_Load = 'Normal'
            print(Memory_Load)
            # Uptime_Status = 'n'
            if Uptime_Status == 'Normal' and Last_Config_change == 'Normal' and CPU_Status == 'Normal' and Memory_Load == 'Normal':
                # net_connect.send_command("clear counters", expect_string="\[confirm\]", delay_factor=5, max_loops=1000)
                # net_connect.send_command('\n', expect_string="#", delay_factor=5, max_loops=1000)
                # time.sleep(5)
                Interface_Details = '\n\nInterface details:\n' + '~' * 100 + '\n'
                Interface_Details += net_connect.send_command('show interfaces | inc reliability| errors| line| drops', delay_factor=5, max_loops=1000)
                value = Interface_Details.split('resets')
                # print(value)
                interface = []
                utilization = []
                Reliability = []
                errors = []
                CRC = []
                drops1 = []
                frame = []
                collisions = []
                for i in value:
                    if 'administratively down' not in str(i) and 'notconnect' not in str(i) and 'disabled' not in str(i) and len(i) >= 100:
                        line_status = re.findall('is ([a-zA-Z]+)', str(i))
                        drops = re.findall('Input queue: \d\/\d+\/([\d])+', str(i))
                        frames = re.findall('([0-9]+) frame', str(i))
                        crc = re.findall('([0-9]+) CRC', str(i))
                        colli = re.findall('([0-9]+) collisions', str(i))
                        for j in line_status:
                            if 'down' in str(j):
                                val = i.split(('\n'))
                                val = str(val[2])
                                interface.append(val.split(' ')[0])
                                print(i.split('\n'))
                                print(interface)
                        txload = re.findall('txload ([0-9]+)', str(i))
                        rxload = re.findall('rxload ([0-9]+)', str(i))
                        print(txload)
                        print(rxload)
                        time.sleep(2)
                        print(len(i))
                        txload_percentage = int(txload[0]) * 100 / int(255)
                        rxload_percentage = int(rxload[0]) * 100 / int(255)
                        if txload_percentage >= 70 or rxload_percentage >= 70:
                            # print('Processor_percentage is high which is ' + str(Processor_percentage) + ' ')
                            utilization.append(i.split(' ')[0])
                        input_errors = re.findall('([0-9]+) input', str(i))
                        output_errors = re.findall('([0-9]+) output', str(i))
                        if int(input_errors[0]) > 0 or int(output_errors[0]) > 0:
                            print(i)
                            val = i.split(('\n'))
                            val = str(val[2])
                            errors.append(val.split(' ')[0])
                        # print(len(colli))
                        if int(frames[0]) > 0:
                            val = i.split(('\n'))
                            val = str(val[2])
                            frame.append(val.split(' ')[0])
                        if int(crc[0]) > 0:
                            val = i.split(('\n'))
                            val = str(val[2])
                            CRC.append(val.split(' ')[0])
                        # print(len(colli))
                        if len(colli) != 0:
                            if int(colli[0]) > 0:
                                val = i.split(('\n'))
                                val = str(val[2])
                                collisions.append(val.split(' ')[0])
                        if int(drops[0]) > 1:
                            val = i.split(('\n'))
                            val = str(val[2])
                            drops1.append(val.split(' ')[0])
                if len(interface) != 0 or len(utilization) != 0 or len(Reliability) != 0 or len(errors) != 0 or len(CRC) != 0 or len(frame) != 0 or len(collisions) != 0 or len(drops1) != 0:
                    print('packet loss happening')
                    issue = 'Manual Action Required'
                else:
                    print('packet loss not happening')
                    issue = 'Device is working fine'
                response_content = issue +'\nDevice name: ' + str(devicename) + ' , IP: ' + str(ip) + '\n Device Current Time: \n' +str(Clock)+ '\nUptime: \n'+ str(Uptime) +'\n Last Config Changed: \n'+str(Last_Config)+'\nCPU Load: \n'+str(CPU_LOAD)+'\nMemory Utilization: \n'+str(Memory_Util)+'\nInterface Details: \n'+str(Interface_Details)
            else:
                response_content = 'Device name: ' + str(devicename) + ' , IP: ' + str(ip) + '\n Device Current Time: \n' + str(Clock) + '\nUptime: \n' + str(Uptime) + '\n Last Config Changed: \n' + str(Last_Config) + '\nCPU Load: \n' + str(CPU_LOAD) + '\nMemory Utilization: \n' + str(Memory_Util)
        except Exception :
            response_content = 'Manual Action Required'
        return response_content
# print(Packet_Loss())
#########################################################################################################################
#########################################################################################################################
