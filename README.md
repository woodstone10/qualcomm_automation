# An Efficient Log Analysis with Automated Filter and Merger

When you received QMDL (captured logs with ODL) logs, what do you usually do first? QMDL has small compressed log (size of 100 Mbyte) and separated several files. In case of automatic saved ISF logs, you will face same situation on separated several files. In driving test, there are dozens of logs its total size over than tens of gigabytes. So it is troublesome and tired to convert ISF and/or replay on QXDM/QCAT due to too many files. 

AutomatedISFFilterAndMerge enable help your easy analysis with a converted (QMDL to ISF), filtered, and merged ISF file. In addition, PCAP file is generated from ISF for DPL analysis. All processing is automation and all thing you do is just C&P (copy and paste) “AutomatedISFFilterAndMerge.pl” to log folter, and run it. Since it done, you will see one ISF file and PCAP file. Filter extracts essential packets from original logs, which reduces QXDM/QCAT replaying time due to slim down. Merger, and, is useful to play QXDM5 and QCAT, because they allow playing one file at one time. Also, generated and merged PCAP saves your time when DPL analysis.

Required software
- Perl software is required (Recommend Strawberry perl, download: http://strawberryperl.com/ )
- Copy and paste HelperFunctions4 on C:\Strawberry\perl\site\lib (just one time)
![image](https://user-images.githubusercontent.com/77954837/114700314-58f5fc00-9d5c-11eb-8785-f620759710d8.png)
- Qualcomm QXDM and QCAT
- Wireshark software is required (download: https://www.wireshark.org/#download)

How to use
- Step.1: copy and past AutomatedISFFilterAndMerge.pl to the target folder
- Step.2: run AutomatedISFFilterAndMerge.pl and type output file name
![image](https://user-images.githubusercontent.com/77954837/114700216-3532b600-9d5c-11eb-9fae-5324953ba6e8.png)
- Step.3: Filtered and merged ISF file, and generated and merged PCAP file
![image](https://user-images.githubusercontent.com/77954837/114700232-3a900080-9d5c-11eb-82f0-cea2de5c7dad.png)

